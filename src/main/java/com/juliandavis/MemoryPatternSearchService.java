package com.juliandavis;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
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
 * Provides methods for finding specific byte patterns in program memory.
 */
public class MemoryPatternSearchService {

    /**
     * Search for a specific pattern of bytes in the program's memory.
     * 
     * @param program The program to search in
     * @param patternHex The pattern to search for (as a hex string)
     * @param searchExecutable Whether to search only in executable memory
     * @param searchOnlyReadable Whether to search only in readable memory
     * @param caseSensitive Whether the search is case sensitive (relevant for ASCII/string searches)
     * @param maxResults Maximum number of results to return (0 for unlimited)
     * @param monitor Task monitor for tracking progress (can be null)
     * @return List of addresses where the pattern was found
     */
    public static List<Map<String, Object>> searchForPattern(
            Program program, 
            String patternHex, 
            boolean searchExecutable, 
            boolean searchOnlyReadable,
            boolean caseSensitive,
            int maxResults,
            TaskMonitor monitor) {
        
        List<Map<String, Object>> results = new ArrayList<>();
        
        if (program == null || patternHex == null || patternHex.isEmpty()) {
            return results;
        }
        
        try {
            // Normalize the pattern (remove spaces if any)
            patternHex = patternHex.replaceAll("\\s", "");
            
            // Check if it's a valid hex string
            if (!patternHex.matches("[0-9A-Fa-f]*")) {
                throw new IllegalArgumentException("Invalid hex pattern: must contain only hex characters");
            }
            
            // Convert hex string to byte array
            if (patternHex.length() % 2 != 0) {
                patternHex = "0" + patternHex; // Pad with leading zero if odd length
            }
            
            byte[] pattern = new byte[patternHex.length() / 2];
            for (int i = 0; i < pattern.length; i++) {
                String byteStr = patternHex.substring(i * 2, i * 2 + 2);
                pattern[i] = (byte) Integer.parseInt(byteStr, 16);
            }
            
            // Alternative pattern if case-insensitive (for ASCII range)
            byte[] patternUpper = null;
            byte[] patternLower = null;
            
            if (!caseSensitive) {
                patternUpper = new byte[pattern.length];
                patternLower = new byte[pattern.length];
                
                for (int i = 0; i < pattern.length; i++) {
                    byte b = pattern[i];
                    if (b >= 'a' && b <= 'z') {
                        patternUpper[i] = (byte) (b - 32); // Convert to uppercase
                        patternLower[i] = b;
                    } else if (b >= 'A' && b <= 'Z') {
                        patternUpper[i] = b;
                        patternLower[i] = (byte) (b + 32); // Convert to lowercase
                    } else {
                        patternUpper[i] = b;
                        patternLower[i] = b;
                    }
                }
            }
            
            // Get memory to search
            Memory memory = program.getMemory();
            AddressSet searchSet = new AddressSet();
            
            // Add memory blocks based on search criteria
            for (MemoryBlock block : memory.getBlocks()) {
                if (searchOnlyReadable && !block.isRead()) {
                    continue;
                }
                
                if (searchExecutable && !block.isExecute()) {
                    continue;
                }
                
                searchSet.add(new AddressRangeImpl(block.getStart(), block.getEnd()));
            }
            
            if (searchSet.isEmpty()) {
                return results; // No blocks to search
            }
            
            // Set up progress monitoring
            TaskMonitor taskMonitor = monitor != null ? monitor : TaskMonitor.DUMMY;
            long totalBytes = getAddressSetSize(searchSet);
            long bytesSearched = 0;
            int resultCount = 0;
            
            // Search through each memory block
            for (AddressRange range : searchSet) {
                Address start = range.getMinAddress();
                Address end = range.getMaxAddress();
                
                // Search in chunks to avoid memory issues with large blocks
                final int CHUNK_SIZE = 1024 * 1024; // 1MB chunks
                Address currentStart = start;
                
                while (currentStart.compareTo(end) <= 0) {
                    // Calculate end of current chunk
                    long remaining = end.subtract(currentStart);
                    long chunkSize = Math.min(remaining, CHUNK_SIZE);
                    Address chunkEnd = currentStart.add(chunkSize);
                    
                    // Read memory chunk
                    byte[] buffer = new byte[(int)chunkSize + 1]; // +1 to read a complete pattern at the end of chunk
                    
                    try {
                        memory.getBytes(currentStart, buffer);
                    } catch (MemoryAccessException e) {
                        // Skip this chunk if we can't read it
                        Msg.warn(MemoryPatternSearchService.class, 
                                "Could not read memory at " + currentStart + ": " + e.getMessage());
                        currentStart = chunkEnd;
                        continue;
                    }
                    
                    // Search for pattern in this buffer
                    List<Integer> offsets = findPatternOffsets(buffer, pattern, patternUpper, patternLower, !caseSensitive);
                    
                    // Convert offsets to addresses and add to results
                    for (Integer offset : offsets) {
                        Address matchAddress = currentStart.add(offset);
                        
                        // Convert to result map
                        Map<String, Object> result = new HashMap<>();
                        result.put("address", matchAddress.toString());
                        
                        // Get some context around the match
                        try {
                            // Try to read some bytes before and after the match for context
                            int contextSize = 8; // 8 bytes before and after
                            Address contextStart = matchAddress.subtract(Math.min(contextSize, matchAddress.getOffset()));
                            int contextLength = pattern.length + 2 * contextSize;
                            
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
                        } catch (Exception e) {
                            // Skip context if we can't read it
                            result.put("context", "");
                        }
                        
                        results.add(result);
                        resultCount++;
                        
                        // Check if we've reached the maximum results
                        if (maxResults > 0 && resultCount >= maxResults) {
                            return results;
                        }
                    }
                    
                    // Update progress
                    bytesSearched += chunkSize;
                    taskMonitor.setProgress(bytesSearched * 100 / totalBytes);
                    if (taskMonitor.isCancelled()) {
                        return results;
                    }
                    
                    // Move to next chunk
                    currentStart = chunkEnd;
                }
            }
            
            return results;
        } catch (Exception e) {
            Msg.error(MemoryPatternSearchService.class, "Error searching for pattern", e);
            return results;
        }
    }
    
    /**
     * Find all occurrences of a pattern in a buffer.
     * 
     * @param buffer The buffer to search in
     * @param pattern The pattern to search for
     * @param patternUpper Uppercase version of pattern (for case insensitive search)
     * @param patternLower Lowercase version of pattern (for case insensitive search)
     * @param caseInsensitive Whether to perform case-insensitive search
     * @return List of offsets where the pattern was found
     */
    private static List<Integer> findPatternOffsets(
            byte[] buffer, 
            byte[] pattern, 
            byte[] patternUpper, 
            byte[] patternLower,
            boolean caseInsensitive) {
        
        List<Integer> results = new ArrayList<>();
        
        // Simple linear search
        for (int i = 0; i <= buffer.length - pattern.length; i++) {
            boolean match = true;
            
            for (int j = 0; j < pattern.length; j++) {
                if (caseInsensitive) {
                    // Check both upper and lower case
                    byte b = buffer[i + j];
                    if (b != patternUpper[j] && b != patternLower[j]) {
                        match = false;
                        break;
                    }
                } else {
                    if (buffer[i + j] != pattern[j]) {
                        match = false;
                        break;
                    }
                }
            }
            
            if (match) {
                results.add(i);
            }
        }
        
        return results;
    }
    
    /**
     * Calculate the total size of an address set in bytes.
     * 
     * @param addressSet The address set
     * @return Total size in bytes
     */
    private static long getAddressSetSize(AddressSet addressSet) {
        long size = 0;
        for (AddressRange range : addressSet) {
            size += range.getLength();
        }
        return size;
    }
}
