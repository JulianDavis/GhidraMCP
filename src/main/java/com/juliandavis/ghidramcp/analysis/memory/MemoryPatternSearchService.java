package com.juliandavis.ghidramcp.analysis.memory;

import com.juliandavis.ghidramcp.core.service.Service;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * Service for searching memory for byte patterns in Ghidra.
 * Uses Ghidra's native Memory.findBytes API for improved performance and flexibility.
 * <p>
 * This implementation supports:
 * - Efficient memory scanning using Ghidra's optimized APIs
 * - Wildcard bytes in patterns using ?? or ** notation
 * - Case-insensitive searches for ASCII text
 * - Contextual information around matches
 */
public class MemoryPatternSearchService implements Service {

    public static final String SERVICE_NAME = "MemoryPatternSearchService";
    
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
     * Search for a specific pattern of bytes in the program's memory.
     * 
     * @param program The program to search in
     * @param patternHex The pattern to search for (as a hex string, can include wildcards with '??')
     * @param searchExecutable Whether to search only in executable memory
     * @param searchOnlyReadable Whether to search only in readable memory
     * @param caseSensitive Whether the search is case-sensitive (relevant for ASCII/string searches)
     * @param maxResults Maximum number of results to return (0 for unlimited)
     * @param monitor Task monitor for tracking progress (can be null)
     * @return Map containing the search results in a standardized format
     */
    public Map<String, Object> searchForPattern(
            Program program, 
            String patternHex, 
            boolean searchExecutable, 
            boolean searchOnlyReadable,
            boolean caseSensitive,
            int maxResults,
            TaskMonitor monitor) {
        
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        if (patternHex == null || patternHex.isEmpty()) {
            return createErrorResponse("Pattern cannot be empty");
        }
        
        try {
            List<Map<String, Object>> results = new ArrayList<>();
            
            // Normalize the pattern (remove spaces if any)
            patternHex = patternHex.replaceAll("\\s", "");
            
            // Parse the pattern into byte array and mask array
            Map<String, byte[]> patternMap = parsePattern(patternHex, caseSensitive);
            byte[] pattern = patternMap.get("pattern");
            byte[] masks = patternMap.get("masks");
            
            // Set up the search area based on criteria
            AddressSet searchSet = new AddressSet();
            Memory memory = program.getMemory();
            
            for (MemoryBlock block : memory.getBlocks()) {
                if (searchOnlyReadable && !block.isRead()) {
                    continue;
                }
                
                if (searchExecutable && !block.isExecute()) {
                    continue;
                }

                // Add the address range of the block to the set
                searchSet.addRange(block.getStart(), block.getEnd());
            }
            
            if (searchSet.isEmpty()) {
                Map<String, Object> responseData = new HashMap<>();
                responseData.put("matches", new ArrayList<>());
                responseData.put("count", 0);
                responseData.put("pattern", patternHex);
                responseData.put("searchCriteria", Map.of(
                    "searchExecutable", searchExecutable,
                    "searchOnlyReadable", searchOnlyReadable,
                    "caseSensitive", caseSensitive,
                    "maxResults", maxResults
                ));
                
                return createSuccessResponse(responseData);
            }
            
            // Set up progress monitoring
            TaskMonitor taskMonitor = monitor != null ? monitor : TaskMonitor.DUMMY;
            int totalRanges = getAddressRangeCount(searchSet);
            int rangesProcessed = 0;
            int resultCount = 0;
            
            taskMonitor.initialize(totalRanges);
            taskMonitor.setMessage("Searching for pattern...");
            
            // Iterate through each range in the AddressSet
            for (AddressRange range : searchSet) {
                Address startAddr = range.getMinAddress();
                Address endAddr = range.getMaxAddress();
                
                taskMonitor.setMessage("Searching range: " + startAddr + " to " + endAddr);
                
                // Search forward through this range
                while (startAddr.compareTo(endAddr) <= 0) {
                    // Check for cancellation
                    if (taskMonitor.isCancelled()) {
                        // Create data for success response with partial results
                        Map<String, Object> responseData = new HashMap<>();
                        responseData.put("matches", results);
                        responseData.put("count", results.size());
                        responseData.put("pattern", patternHex);
                        responseData.put("cancelled", true);
                        responseData.put("searchCriteria", Map.of(
                            "searchExecutable", searchExecutable,
                            "searchOnlyReadable", searchOnlyReadable,
                            "caseSensitive", caseSensitive,
                            "maxResults", maxResults
                        ));
                        
                        return createSuccessResponse(responseData);
                    }
                    
                    // Find the next occurrence using Ghidra's findBytes API
                    Address foundAddr = memory.findBytes(startAddr, endAddr, pattern, masks, true, taskMonitor);
                    
                    if (foundAddr == null) {
                        break; // No more matches in this range
                    }
                    
                    // Add to results
                    Map<String, Object> result = new HashMap<>();
                    result.put("address", foundAddr.toString());
                    
                    // Get the containing memory block
                    MemoryBlock block = memory.getBlock(foundAddr);
                    if (block != null) {
                        result.put("blockName", block.getName());
                        result.put("blockPermissions", String.format("%s%s%s",
                                block.isRead() ? "r" : "-",
                                block.isWrite() ? "w" : "-",
                                block.isExecute() ? "x" : "-"));
                    }
                    
                    // Get context around the match
                    addContextToResult(memory, foundAddr, pattern.length, result);
                    
                    results.add(result);
                    resultCount++;
                    
                    // Update progress
                    if (resultCount % 100 == 0) {
                        taskMonitor.setMessage("Found " + resultCount + " matches so far...");
                    }
                    
                    // Check if we've reached max results
                    if (maxResults > 0 && resultCount >= maxResults) {
                        taskMonitor.setMessage("Reached maximum requested results: " + maxResults);
                        
                        // Create data for success response
                        Map<String, Object> responseData = new HashMap<>();
                        responseData.put("matches", results);
                        responseData.put("count", results.size());
                        responseData.put("pattern", patternHex);
                        responseData.put("searchCriteria", Map.of(
                            "searchExecutable", searchExecutable,
                            "searchOnlyReadable", searchOnlyReadable,
                            "caseSensitive", caseSensitive,
                            "maxResults", maxResults
                        ));
                        
                        return createSuccessResponse(responseData);
                    }
                    
                    // Move to position after this match for next search
                    startAddr = foundAddr.add(1);
                }
                
                // Update progress after each range
                rangesProcessed++;
                taskMonitor.setProgress(rangesProcessed);
            }
            
            taskMonitor.setMessage("Search complete. Found " + resultCount + " matches.");
            
            // Create data for success response
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("matches", results);
            responseData.put("count", results.size());
            responseData.put("pattern", patternHex);
            responseData.put("searchCriteria", Map.of(
                "searchExecutable", searchExecutable,
                "searchOnlyReadable", searchOnlyReadable,
                "caseSensitive", caseSensitive,
                "maxResults", maxResults
            ));
            
            return createSuccessResponse(responseData);
        } catch (Exception e) {
            Msg.error(MemoryPatternSearchService.class, "Error searching for pattern", e);
            return createErrorResponse("Error searching for pattern: " + e.getMessage());
        }
    }
    
    /**
     * Parse a hex pattern string into pattern and mask byte arrays.
     * 
     * @param patternHex The pattern in hex format
     * @param caseSensitive Whether the search is case-sensitive
     * @return Map containing "pattern" and "masks" byte arrays
     * @throws IllegalArgumentException If the pattern is invalid
     */
    private Map<String, byte[]> parsePattern(String patternHex, boolean caseSensitive) {
        // If odd length, pad with leading zero
        if (patternHex.length() % 2 != 0) {
            patternHex = "0" + patternHex;
        }
        
        // Check if it's a valid hex string with possible wildcards
        if (!isValidPatternString(patternHex)) {
            throw new IllegalArgumentException("Invalid hex pattern: must contain only hex characters or wildcards (??)");
        }
        
        List<Byte> patternBytes = new ArrayList<>();
        List<Byte> maskBytes = new ArrayList<>();
        
        // Process pattern two characters at a time (one byte)
        for (int i = 0; i < patternHex.length(); i += 2) {
            String byteStr = patternHex.substring(i, i + 2);
            
            // Handle wildcard bytes
            if (byteStr.equals("??") || byteStr.equals("**")) {
                patternBytes.add((byte) 0);   // Value doesn't matter when mask is 0
                maskBytes.add((byte) 0);      // Mask of 0 means ignore all bits
                continue;
            }
            
            // Parse normal hex byte
            byte b = (byte) Integer.parseInt(byteStr, 16);
            patternBytes.add(b);
            
            // If case-insensitive and byte is ASCII letter, modify mask
            if (!caseSensitive && isAsciiLetter(b)) {
                maskBytes.add((byte) 0xDF);  // Mask off bit 5 (case bit for ASCII)
            } else {
                maskBytes.add((byte) 0xFF);  // Full mask - all bits must match
            }
        }
        
        // Convert to primitive arrays
        byte[] pattern = new byte[patternBytes.size()];
        byte[] masks = new byte[maskBytes.size()];
        
        for (int i = 0; i < patternBytes.size(); i++) {
            pattern[i] = patternBytes.get(i);
            masks[i] = maskBytes.get(i);
        }
        
        Map<String, byte[]> result = new HashMap<>();
        result.put("pattern", pattern);
        result.put("masks", masks);
        
        return result;
    }
    
    /**
     * Add contextual information to a search result
     */
    private void addContextToResult(Memory memory, Address address, int patternLength, Map<String, Object> result) {
        try {
            // Try to read some bytes before and after the match for context
            int contextSize = 8; // 8 bytes before and after
            Address contextStart = address.subtract(Math.min(contextSize, address.getOffset()));
            int contextLength = patternLength + 2 * contextSize;
            
            byte[] context = new byte[contextLength];
            memory.getBytes(contextStart, context);
            
            // Format as hex
            StringBuilder hexContext = new StringBuilder();
            for (int i = 0; i < context.length; i++) {
                if (i > 0) hexContext.append(" ");
                hexContext.append(String.format("%02X", context[i] & 0xFF));
            }
            
            result.put("context", hexContext.toString());
            result.put("contextStart", contextStart.toString());
        } catch (MemoryAccessException e) {
            // Skip context if we can't read it
            result.put("context", "");
        }
    }
    
    /**
     * Check if a byte represents an ASCII letter (A-Z, a-z)
     */
    private boolean isAsciiLetter(byte b) {
        return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z');
    }
    
    /**
     * Check if a pattern string is valid (hex digits and wildcards)
     */
    private boolean isValidPatternString(String pattern) {
        for (int i = 0; i < pattern.length(); i += 2) {
            if (i + 1 >= pattern.length()) {
                return false; // Odd length
            }
            
            String pair = pattern.substring(i, i + 2);
            if (pair.equals("??") || pair.equals("**")) {
                continue; // Valid wildcard
            }
            
            // Check if hex
            try {
                Integer.parseInt(pair, 16);
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * Count the number of address ranges in an AddressSet
     */
    private int getAddressRangeCount(AddressSet addressSet) {
        int count = 0;
        for (AddressRange ignored : addressSet) {
            count++;
        }
        return count;
    }
}