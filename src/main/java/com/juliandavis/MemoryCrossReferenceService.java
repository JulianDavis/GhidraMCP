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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

/**
 * Service for finding cross-references to memory addresses in Ghidra.
 * Provides methods to scan memory for potential references to a target address or address range.
 */
public class MemoryCrossReferenceService {

    /**
     * Find all memory locations that potentially reference a target address.
     * 
     * @param program The program to search in
     * @param targetAddressStr The target address to find references to (as a string)
     * @param searchOnlyExecutable Whether to search only in executable memory
     * @param searchOnlyReadable Whether to search only in readable memory
     * @param maxResults Maximum number of results to return (0 for unlimited)
     * @param monitor Task monitor for tracking progress (can be null)
     * @return List of addresses where references were found
     */
    public static List<Map<String, Object>> findReferences(
            Program program, 
            String targetAddressStr, 
            boolean searchOnlyExecutable, 
            boolean searchOnlyReadable,
            int maxResults,
            TaskMonitor monitor) {
        
        List<Map<String, Object>> results = new ArrayList<>();
        
        if (program == null || targetAddressStr == null || targetAddressStr.isEmpty()) {
            return results;
        }
        
        try {
            // Parse target address
            Address targetAddress = program.getAddressFactory().getAddress(targetAddressStr);
            if (targetAddress == null) {
                throw new IllegalArgumentException("Invalid target address: " + targetAddressStr);
            }
            
            long targetAddressValue = targetAddress.getOffset();
            
            // Get memory to search
            Memory memory = program.getMemory();
            AddressSet searchSet = new AddressSet();
            
            // Add memory blocks based on search criteria
            for (MemoryBlock block : memory.getBlocks()) {
                if (searchOnlyReadable && !block.isRead()) {
                    continue;
                }
                
                if (searchOnlyExecutable && !block.isExecute()) {
                    continue;
                }
                
                searchSet.add(new AddressRangeImpl(block.getStart(), block.getEnd()));
            }
            
            if (searchSet.isEmpty()) {
                return results; // No blocks to search
            }
            
            // Get pointer size based on program architecture
            int pointerSize = program.getLanguage().getLanguageDescription().getSize() / 8;
            boolean isBigEndian = program.getLanguage().isBigEndian();
            
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
                    byte[] buffer = new byte[(int)chunkSize];
                    
                    try {
                        memory.getBytes(currentStart, buffer);
                    } catch (MemoryAccessException e) {
                        // Skip this chunk if we can't read it
                        Msg.warn(MemoryCrossReferenceService.class, 
                                "Could not read memory at " + currentStart + ": " + e.getMessage());
                        currentStart = chunkEnd;
                        continue;
                    }
                    
                    // Search for references in this buffer
                    List<Integer> offsets = findAddressReferences(
                            buffer, targetAddressValue, pointerSize, isBigEndian);
                    
                    // Convert offsets to addresses and add to results
                    for (Integer offset : offsets) {
                        Address refAddress = currentStart.add(offset);
                        
                        // Convert to result map
                        Map<String, Object> result = new HashMap<>();
                        result.put("referenceAddress", refAddress.toString());
                        result.put("targetAddress", targetAddress.toString());
                        result.put("referenceType", "DATA"); // Default to data reference
                        
                        // Try to get the containing memory block
                        MemoryBlock block = memory.getBlock(refAddress);
                        if (block != null) {
                            result.put("blockName", block.getName());
                            result.put("blockPermissions", String.format("%s%s%s",
                                    block.isRead() ? "r" : "-",
                                    block.isWrite() ? "w" : "-",
                                    block.isExecute() ? "x" : "-"));
                            
                            // If in executable memory, it might be a code reference
                            if (block.isExecute()) {
                                result.put("referenceType", "CODE");
                            }
                        }
                        
                        // Get context around the reference
                        try {
                            byte[] context = new byte[pointerSize * 3]; // Read 3 pointers worth of context
                            int contextOffset = Math.max(0, offset - pointerSize);
                            int readSize = Math.min(buffer.length - contextOffset, context.length);
                            System.arraycopy(buffer, contextOffset, context, 0, readSize);
                            
                            // Format as hex
                            StringBuilder hexContext = new StringBuilder();
                            for (int i = 0; i < readSize; i++) {
                                if (i > 0 && i % 4 == 0) hexContext.append(" ");
                                hexContext.append(String.format("%02X", context[i] & 0xFF));
                            }
                            
                            result.put("context", hexContext.toString());
                        } catch (Exception e) {
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
            Msg.error(MemoryCrossReferenceService.class, "Error finding references", e);
            return results;
        }
    }
    
    /**
     * Find all references to an address in a buffer.
     * 
     * @param buffer The buffer to search in
     * @param targetAddress The target address value to find
     * @param pointerSize Size of pointers in bytes
     * @param isBigEndian Whether the architecture is big-endian
     * @return List of offsets where references were found
     */
    private static List<Integer> findAddressReferences(
            byte[] buffer, 
            long targetAddress, 
            int pointerSize,
            boolean isBigEndian) {
        
        List<Integer> results = new ArrayList<>();
        
        // For each possible pointer location
        for (int i = 0; i <= buffer.length - pointerSize; i++) {
            ByteBuffer bb = ByteBuffer.wrap(buffer, i, pointerSize);
            if (isBigEndian) {
                bb.order(ByteOrder.BIG_ENDIAN);
            } else {
                bb.order(ByteOrder.LITTLE_ENDIAN);
            }
            
            long value = readAddressValue(bb, pointerSize);
            
            // Check if this value matches our target address
            if (value == targetAddress) {
                results.add(i);
            }
        }
        
        return results;
    }
    
    /**
     * Read an address value from a ByteBuffer based on pointer size.
     * 
     * @param buffer The ByteBuffer to read from
     * @param pointerSize Size of the pointer in bytes
     * @return The address value as a long
     */
    private static long readAddressValue(ByteBuffer buffer, int pointerSize) {
        switch (pointerSize) {
            case 1:
                return buffer.get() & 0xFF;
            case 2:
                return buffer.getShort() & 0xFFFF;
            case 4:
                return buffer.getInt() & 0xFFFFFFFFL;
            case 8:
                return buffer.getLong();
            default:
                throw new IllegalArgumentException("Unsupported pointer size: " + pointerSize);
        }
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
