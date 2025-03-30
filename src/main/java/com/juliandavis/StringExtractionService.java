package com.juliandavis;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.string.FoundString;
import ghidra.program.util.string.FoundStringCallback;
import ghidra.program.util.string.StringSearcher;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * Service for extracting strings from memory in Ghidra.
 * Uses Ghidra's native StringSearcher API for robust string detection.
 * <p>
 * This implementation supports:
 * - ASCII, Unicode (UTF-16/UTF-32), and other string encodings
 * - Minimum length filtering
 * - Restricting searches to specific memory regions
 * - Contextual information about found strings
 */
public class StringExtractionService {

    /**
     * String encoding types that can be searched for
     */
    public enum StringEncoding {
        ASCII,
        UNICODE,
        ALL
    }

    /**
     * Extract strings from program memory.
     * 
     * @param program The program to search in
     * @param minLength Minimum string length to consider
     * @param encoding String encoding to search for (ASCII, UNICODE, or ALL)
     * @param searchRWMemory Whether to search in read-write memory segments
     * @param searchROMemory Whether to search in read-only memory segments
     * @param searchExecutableMemory Whether to search in executable memory segments
     * @param maxResults Maximum number of results to return (0 for unlimited)
     * @param monitor Task monitor for tracking progress (can be null)
     * @return List of maps containing string information
     */
    public static List<Map<String, Object>> extractStrings(
            Program program,
            int minLength,
            StringEncoding encoding,
            boolean searchRWMemory,
            boolean searchROMemory,
            boolean searchExecutableMemory,
            int maxResults,
            TaskMonitor monitor) {
        
        List<Map<String, Object>> results = new ArrayList<>();
        
        if (program == null || minLength < 1) {
            return results;
        }
        
        try {
            // Use a dummy monitor if none provided
            TaskMonitor taskMonitor = monitor != null ? monitor : TaskMonitor.DUMMY;
            taskMonitor.setMessage("Preparing string extraction...");
            
            // Set up the search area based on criteria
            AddressSet searchSet = new AddressSet();
            
            // Add blocks based on permissions
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                boolean isReadWrite = block.isRead() && block.isWrite() && !block.isExecute();
                boolean isReadOnly = block.isRead() && !block.isWrite() && !block.isExecute();
                boolean isExecutable = block.isExecute();
                
                if ((searchRWMemory && isReadWrite) || 
                    (searchROMemory && isReadOnly) || 
                    (searchExecutableMemory && isExecutable)) {
                    
                    searchSet.addRange(block.getStart(), block.getEnd());
                }
            }
            
            if (searchSet.isEmpty()) {
                return results;
            }
            
            // Create StringSearcher with appropriate settings
            StringSearcher stringSearcher;
            
            // Configure string searcher based on encoding parameter
            boolean allCharSizes = encoding == StringEncoding.ALL || encoding == StringEncoding.UNICODE;
            
            // Create the StringSearcher
            // Parameters: program, minimumStringSize, alignment, allCharSizes, requireNullTermination
            stringSearcher = new StringSearcher(program, minLength, 1, allCharSizes, false);
            
            // Track progress
            taskMonitor.setMessage("Searching for strings...");
            
            // Create a callback to collect results
            StringCollector collector = new StringCollector(program, maxResults);
            
            // Perform the search
            stringSearcher.search(searchSet, collector, false, taskMonitor);
            
            // Get the results
            results = collector.getResults();
            
            taskMonitor.setMessage("Found " + results.size() + " strings.");
            return results;
            
        } catch (Exception e) {
            Msg.error(StringExtractionService.class, "Error extracting strings", e);
            return results;
        }
    }
    
    /**
     * Callback implementation that collects found strings
     */
    private static class StringCollector implements FoundStringCallback {
        private final List<Map<String, Object>> results = new ArrayList<>();
        private final Program program;
        private final int maxResults;
        private final Memory memory;
        private boolean limitReached = false;
        
        public StringCollector(Program program, int maxResults) {
            this.program = program;
            this.maxResults = maxResults;
            this.memory = program.getMemory();
        }
        
        @Override
        public void stringFound(FoundString foundString) {
            // Check if we've reached the limit
            if (maxResults > 0 && results.size() >= maxResults) {
                limitReached = true;
                return;
            }
            
            try {
                Map<String, Object> stringInfo = new HashMap<>();
                Address address = foundString.getAddress();
                String stringValue = foundString.getString(memory);
                
                // Add basic info
                stringInfo.put("address", address.toString());
                stringInfo.put("value", stringValue);
                stringInfo.put("length", foundString.getLength());
                
                // Determine encoding based on data type
                String encodingName = "ASCII";
                if (foundString.getDataType().getName().contains("Unicode")) {
                    encodingName = "Unicode";
                }
                stringInfo.put("encoding", encodingName);
                
                // Add block info
                MemoryBlock block = memory.getBlock(address);
                if (block != null) {
                    stringInfo.put("blockName", block.getName());
                    stringInfo.put("blockType", getBlockType(block));
                    stringInfo.put("blockPermissions", String.format("%s%s%s",
                            block.isRead() ? "r" : "-",
                            block.isWrite() ? "w" : "-",
                            block.isExecute() ? "x" : "-"));
                }
                
                // Try to get data references to this string
                List<Map<String, Object>> references = getReferencesToString(program, address);
                if (!references.isEmpty()) {
                    stringInfo.put("references", references);
                    stringInfo.put("referenceCount", references.size());
                }
                
                results.add(stringInfo);
            } catch (Exception e) {
                Msg.trace(this, "Error processing found string at " + foundString.getAddress() + ": " + e.getMessage());
            }
        }
        
        public List<Map<String, Object>> getResults() {
            return results;
        }
        
        public boolean isLimitReached() {
            return limitReached;
        }
    }
    
    /**
     * Get a descriptive type for the memory block
     */
    private static String getBlockType(MemoryBlock block) {
        if (block.isExecute()) {
            return "Executable";
        } else if (block.isWrite()) {
            return "Read-Write";
        } else if (block.isRead()) {
            return "Read-Only";
        } else {
            return "Other";
        }
    }
    
    /**
     * Get references to a string at a specific address
     */
    private static List<Map<String, Object>> getReferencesToString(Program program, Address address) {
        List<Map<String, Object>> references = new ArrayList<>();
        
        try {
            for (ghidra.program.model.symbol.Reference ref : program.getReferenceManager().getReferencesTo(address)) {
                Map<String, Object> refInfo = new HashMap<>();
                refInfo.put("fromAddress", ref.getFromAddress().toString());
                refInfo.put("type", ref.getReferenceType().getName());
                
                // Try to get function containing the reference
                ghidra.program.model.listing.Function function = 
                        program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                
                if (function != null) {
                    refInfo.put("function", function.getName());
                    refInfo.put("functionAddress", function.getEntryPoint().toString());
                }
                
                references.add(refInfo);
            }
        } catch (Exception e) {
            // Ignore errors in getting references
        }
        
        return references;
    }
}
