package com.juliandavis.ghidramcp.analysis.search;

import com.juliandavis.ghidramcp.core.service.Service;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
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
public class StringExtractionService implements Service {

    public static final String SERVICE_NAME = "StringExtractionService";

    /**
     * Get the service name
     *
     * @return The service name
     */
    @Override
    public String getName() {
        return SERVICE_NAME;
    }

    /**
     * Initialize the service with the current program.
     *
     * @param program the current Ghidra program
     */
    @Override
    public void initialize(Program program) {
        // No initialization required
    }

    /**
     * Dispose of service resources
     */
    @Override
    public void dispose() {
        // No resources to dispose
    }
    
    /**
     * Creates a standardized error response with default error code (400)
     * 
     * @param errorMessage The error message
     * @return Map representing the error response
     */
    private Map<String, Object> createErrorResponse(String errorMessage) {
        return createErrorResponse(errorMessage, 400);
    }
    
    /**
     * Creates a standardized error response
     * 
     * @param errorMessage The error message
     * @param errorCode Optional error code
     * @return Map representing the error response
     */
    private Map<String, Object> createErrorResponse(String errorMessage, int errorCode) {
        Map<String, Object> response = new HashMap<>();
        Map<String, Object> errorDetails = new HashMap<>();
        
        // Standard top-level structure
        response.put("status", "error");
        
        // Error details
        errorDetails.put("message", errorMessage);
        errorDetails.put("code", errorCode);
        
        response.put("error", errorDetails);
        
        return response;
    }
    
    /**
     * Creates a standardized success response
     * 
     * @param data The data to include in the response
     * @return Map representing the success response
     */
    private Map<String, Object> createSuccessResponse(Map<String, Object> data) {
        Map<String, Object> response = new HashMap<>();
        
        // Standard top-level structure
        response.put("status", "success");
        response.put("data", data);
        
        return response;
    }

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
     * @param program              The program to search in
     * @param minLength            Minimum string length to consider
     * @param encoding             String encoding to search for (ASCII, UNICODE, or ALL)
     * @param searchRWMemory       Whether to search in read-write memory segments
     * @param searchROMemory       Whether to search in read-only memory segments
     * @param searchExecutableMemory Whether to search in executable memory segments
     * @param maxResults           Maximum number of results to return (0 for unlimited)
     * @param monitor              Task monitor for tracking progress (can be null)
     * @return List of maps containing string information
     */
    public Map<String, Object> extractStrings(
            Program program,
            int minLength,
            StringEncoding encoding,
            boolean searchRWMemory,
            boolean searchROMemory,
            boolean searchExecutableMemory,
            int maxResults,
            TaskMonitor monitor) {

        if (program == null || minLength < 1) {
            Msg.warn(StringExtractionService.class, "Invalid program or minimum length provided.");
            return createErrorResponse("Invalid program or minimum length provided");
        }
        
        List<Map<String, Object>> results = new ArrayList<>();

        try {
            // Use a dummy monitor if none provided
            TaskMonitor taskMonitor = monitor != null ? monitor : TaskMonitor.DUMMY;
            taskMonitor.initialize(program.getMemory().getSize(), "Extracting Strings"); // Initialize monitor

            taskMonitor.setMessage("Preparing string extraction: Determining search area...");

            // Set up the search area based on criteria
            AddressSet searchSet = new AddressSet();
            Memory memory = program.getMemory();

            // Add blocks based on permissions
            for (MemoryBlock block : memory.getBlocks()) {
                if (taskMonitor.isCancelled()) {
                    // Create data for success response with partial results
                    Map<String, Object> responseData = new HashMap<>();
                    responseData.put("strings", results);
                    responseData.put("count", results.size());
                    responseData.put("minLength", minLength);
                    responseData.put("encoding", encoding.toString());
                    responseData.put("cancelled", true);
                    responseData.put("searchCriteria", Map.of(
                        "searchRWMemory", searchRWMemory,
                        "searchROMemory", searchROMemory,
                        "searchExecutableMemory", searchExecutableMemory,
                        "maxResults", maxResults
                    ));
                    
                    return createSuccessResponse(responseData);
                }
                boolean isReadWrite = block.isRead() && block.isWrite(); // Consider RW regardless of execute
                boolean isReadOnly = block.isRead() && !block.isWrite();
                boolean isExecutable = block.isExecute();

                boolean includeBlock = false;
                if (searchRWMemory && isReadWrite) {
                    includeBlock = true;
                }
                if (searchROMemory && isReadOnly) {
                    includeBlock = true;
                }
                // Note: Executable memory can also be R or RW.
                // This logic includes a block if *any* matching permission criteria is met.
                // If specifically *only* executable is desired (and not RW/RO), logic needs adjustment.
                if (searchExecutableMemory && isExecutable) {
                    includeBlock = true;
                }

                if (includeBlock) {
                    searchSet.addRange(block.getStart(), block.getEnd());
                }
            }

            if (searchSet.isEmpty()) {
                Msg.info(StringExtractionService.class, "No memory blocks match the specified search criteria.");
                
                // Create empty result
                Map<String, Object> responseData = new HashMap<>();
                responseData.put("strings", new ArrayList<>());
                responseData.put("count", 0);
                responseData.put("minLength", minLength);
                responseData.put("encoding", encoding.toString());
                responseData.put("searchCriteria", Map.of(
                    "searchRWMemory", searchRWMemory,
                    "searchROMemory", searchROMemory,
                    "searchExecutableMemory", searchExecutableMemory,
                    "maxResults", maxResults
                ));
                
                return createSuccessResponse(responseData);
            }

            taskMonitor.setMessage("Setting up StringSearcher...");

            // Create StringSearcher with appropriate settings
            // Configure string searcher based on encoding parameter
            // Ghidra's 'allCharSizes' = true searches for ASCII (1-byte) and Unicode (2 & 4 byte).
            boolean searchAscii = encoding == StringEncoding.ASCII || encoding == StringEncoding.ALL;
            boolean searchUnicode = encoding == StringEncoding.UNICODE || encoding == StringEncoding.ALL;

            // We might need two separate searches if only one type is requested explicitly,
            // or handle filtering in the callback. Using allCharSizes is simpler if ALL or UNICODE.
            // Let's use the simpler approach first. `allCharSizes=true` covers ASCII & Unicode.
            // If only ASCII is needed, `allCharSizes=false` would be more efficient.
            boolean useAllCharSizes = searchUnicode; // True if UNICODE or ALL

            // Create the StringSearcher
            // Parameters: program, minimumStringSize, alignment, allCharSizes, requireNullTermination
            // Alignment=1 checks every byte. requireNullTermination=false finds unterminated strings.
            StringSearcher stringSearcher = new StringSearcher(program, minLength, 1, useAllCharSizes, false);

            // TODO: Add configuration for null termination if needed
            // TODO: Add configuration for specific character sets if needed beyond ASCII/Unicode

            // Track progress
            taskMonitor.setMessage("Searching for strings in selected memory...");

            // Create a callback to collect results
            StringCollector collector = new StringCollector(program, maxResults, encoding);

            // Perform the search
            stringSearcher.search(searchSet, collector, true, taskMonitor); // Use true for forward search

            // Get the results
            results = collector.getResults();

            if (collector.isLimitReached()) {
                taskMonitor.setMessage("Reached maximum results limit (" + maxResults + "). Found " + results.size() + " strings.");
            } else if (taskMonitor.isCancelled()) {
                taskMonitor.setMessage("String search cancelled. Found " + results.size() + " strings.");
            } else {
                taskMonitor.setMessage("String search complete. Found " + results.size() + " strings.");
            }
            
            // Create data for success response
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("strings", results);
            responseData.put("count", results.size());
            responseData.put("minLength", minLength);
            responseData.put("encoding", encoding.toString());
            responseData.put("searchCriteria", Map.of(
                "searchRWMemory", searchRWMemory,
                "searchROMemory", searchROMemory,
                "searchExecutableMemory", searchExecutableMemory,
                "maxResults", maxResults
            ));
            
            return createSuccessResponse(responseData);

        } catch (Exception e) {
            Msg.error(StringExtractionService.class, "Error extracting strings", e);
            return createErrorResponse("Error extracting strings: " + e.getMessage());
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

    /**
     * Callback implementation that collects found strings
     */
    private static class StringCollector implements FoundStringCallback {
        private final List<Map<String, Object>> results = new ArrayList<>();
        private final Program program;
        private final int maxResults;
        private final Memory memory;
        private final StringEncoding requestedEncoding;
        private boolean limitReached = false;

        public StringCollector(Program program, int maxResults, StringEncoding requestedEncoding) {
            this.program = program;
            this.maxResults = (maxResults <= 0) ? Integer.MAX_VALUE : maxResults; // Use max int if 0 or less
            this.memory = program.getMemory();
            this.requestedEncoding = requestedEncoding;
        }

        @Override
        public void stringFound(FoundString foundString) {
            // Check if we've already reached the limit
            if (limitReached || results.size() >= maxResults) {
                limitReached = true;
                // We need to tell StringSearcher to stop, but the API doesn't directly support it from here.
                // It relies on TaskMonitor.isCancelled(). We'll just stop adding results.
                return;
            }

            try {
                Map<String, Object> stringInfo = new HashMap<>();
                Address address = foundString.getAddress();
                String stringValue = foundString.getString(memory); // Can throw MemoryAccessException
                int length = foundString.getLength(); // Length in bytes
                String actualEncodingName = getEncodingName(foundString);

                // Filter by requested encoding if necessary (StringSearcher might find both)
                if (requestedEncoding == StringEncoding.ASCII && !actualEncodingName.equals("ASCII")) {
                    return; // Skip if we only wanted ASCII but found Unicode
                }
                if (requestedEncoding == StringEncoding.UNICODE && actualEncodingName.equals("ASCII")) {
                    return; // Skip if we only wanted Unicode but found ASCII
                }

                // Add basic info
                stringInfo.put("address", address.toString());
                stringInfo.put("value", stringValue);
                stringInfo.put("lengthBytes", length); // Length in bytes
                stringInfo.put("lengthChars", stringValue.length()); // Length in characters
                stringInfo.put("encoding", actualEncodingName);

                // TODO: Fix this crap lol
                // Check if string appears to be null terminated - replaces direct call to isPossibleNullTerminated()
                boolean isNullTerminated = false;
                if (foundString.getDataType() != null) {
                    String dtName = foundString.getDataType().getName().toLowerCase();
                    isNullTerminated = dtName.contains("terminated") || dtName.contains("null");
                }
                stringInfo.put("isTerminated", isNullTerminated); // If it seems null terminated

                // Add block info
                MemoryBlock block = memory.getBlock(address);
                if (block != null) {
                    stringInfo.put("blockName", block.getName());
                    stringInfo.put("blockType", getBlockTypeString(block));
                    stringInfo.put("blockPermissions", String.format("%s%s%s",
                            block.isRead() ? "r" : "-",
                            block.isWrite() ? "w" : "-",
                            block.isExecute() ? "x" : "-"));
                } else {
                    stringInfo.put("blockName", "[Unknown]");
                    stringInfo.put("blockType", "[Unknown]");
                    stringInfo.put("blockPermissions", "---");
                }

                // Try to get data references *to* this string's address
                // Note: This only finds references *to the start* of the string.
                List<Map<String, Object>> references = getReferencesToAddress(program, address);
                if (!references.isEmpty()) {
                    stringInfo.put("referencesTo", references);
                    stringInfo.put("referenceToCount", references.size());
                } else {
                    stringInfo.put("referenceToCount", 0);
                }

                results.add(stringInfo);

                // Check limit again after adding
                if (results.size() >= maxResults) {
                    limitReached = true;
                }

            } catch (Exception e) {
                // Catch broader exceptions to prevent stopping the entire search
                Msg.error(this, "Error processing found string at " + foundString.getAddress(), e);
            }
        }

        // Helper to determine encoding name from FoundString
        private String getEncodingName(FoundString fs) {
            // FoundString doesn't directly expose encoding easily, infer from data type
            // This is heuristic. DataType might not be set if string isn't defined in Listing.
            if (fs.getDataType() != null) {
                String dtName = fs.getDataType().getName().toLowerCase();
                if (dtName.contains("unicode")) {
                    // Could check for utf16, utf32 etc. if needed
                    return "Unicode";
                } else if (dtName.contains("string") || dtName.contains("char")) {
                    // Assume ASCII/single-byte if not unicode
                    return "ASCII";
                }
            }


            // https://ghidra.re/ghidra_docs/api/ghidra/program/util/string/FoundString.html
            // TODO: Implement proper character size detection
            // Since we can't directly access getCharSize, make a reasonable inference
            // based on string length vs byte length
            try {
                String stringVal = fs.getString(memory);
                int byteLength = fs.getLength();
                int charLength = stringVal.length();
                
                // If the byte length is significantly greater than char length, likely Unicode
                if (byteLength > (charLength * 1.5)) {
                    return "Unicode"; // Likely UTF-16 or UTF-32
                } else {
                    return "ASCII"; // Default to ASCII
                }
            } catch (Exception e) {
                return "ASCII"; // Default if we can't determine
            }
        }

        // Helper to classify block type (simplified)
        private static String getBlockTypeString(MemoryBlock block) {
            if (block.isExecute()) return "Executable";
            if (block.isWrite()) return "Read-Write";
            if (block.isRead()) return "Read-Only";
            return "Unknown";
        }

        // Helper to get references TO a specific address
        private static List<Map<String, Object>> getReferencesToAddress(Program program, Address targetAddress) {
            List<Map<String, Object>> refList = new ArrayList<>();
            ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(targetAddress);
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Map<String, Object> refInfo = new HashMap<>();
                refInfo.put("fromAddress", ref.getFromAddress().toString());
                refInfo.put("type", ref.getReferenceType().toString());
                refInfo.put("isPrimary", ref.isPrimary());
                refList.add(refInfo);
            }
            return refList;
        }

        public List<Map<String, Object>> getResults() {
            return results;
        }

        public boolean isLimitReached() {
            return limitReached;
        }
    }
}
