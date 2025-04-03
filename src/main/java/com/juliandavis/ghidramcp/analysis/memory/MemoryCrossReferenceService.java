package com.juliandavis.ghidramcp.analysis.memory;

import com.juliandavis.ghidramcp.core.service.Service;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

/**
 * Service for finding cross-references to memory addresses in Ghidra.
 * Provides methods to:
 * 1. Get known references from Ghidra's ReferenceManager
 * 2. Scan memory for potential references not tracked by Ghidra
 */
public class MemoryCrossReferenceService implements Service {

    private static final String SERVICE_NAME = "MemoryCrossReferenceService";

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
     * Read an address value from a ByteBuffer based on pointer size.
     *
     * @param buffer The ByteBuffer to read from
     * @param pointerSize Size of the pointer in bytes
     * @return The address value as a long
     */
    private long readAddressValue(ByteBuffer buffer, int pointerSize) {
        return switch (pointerSize) {
            case 1 -> buffer.get() & 0xFF;
            case 2 -> buffer.getShort() & 0xFFFF;
            case 4 -> buffer.getInt() & 0xFFFFFFFFL;
            case 8 -> buffer.getLong();
            default -> throw new IllegalArgumentException("Unsupported pointer size: " + pointerSize);
        };
    }

    /**
     * Combined reference search that first gets known references, then performs a memory scan if requested.
     *
     * @param program The program to search in
     * @param targetAddressStr The target address to find references to (as a string)
     * @param includeMemoryScan Whether to perform a memory scan for potential references
     * @param searchOnlyExecutable For memory scan: whether to search only in executable memory
     * @param searchOnlyReadable For memory scan: whether to search only in readable memory
     * @param maxScanResults For memory scan: maximum number of results to return (0 for unlimited)
     * @param monitor Task monitor for tracking progress (can be null)
     * @return Combined list of both known and discovered references
     */
    public Map<String, Object> findAllReferences(
            Program program,
            String targetAddressStr,
            boolean includeMemoryScan,
            boolean searchOnlyExecutable,
            boolean searchOnlyReadable,
            int maxScanResults,
            TaskMonitor monitor) {

        Map<String, Object> result = new HashMap<>();

        try {
            // First, get known references from the ReferenceManager
            List<Map<String, Object>> knownRefs = getKnownReferences(program, targetAddressStr, monitor);

            List<Map<String, Object>> discoveredRefs = new ArrayList<>();

            // Then, if requested, scan memory for additional potential references
            if (includeMemoryScan) {
                discoveredRefs = findPotentialReferences(
                        program,
                        targetAddressStr,
                        searchOnlyExecutable,
                        searchOnlyReadable,
                        maxScanResults,
                        monitor);

                // Filter out any discovered references that match known references
                // to avoid duplicates
                Set<String> knownAddresses = new HashSet<>();
                for (Map<String, Object> ref : knownRefs) {
                    knownAddresses.add((String)ref.get("referenceAddress"));
                }

                List<Map<String, Object>> uniqueDiscoveredRefs = new ArrayList<>();
                for (Map<String, Object> ref : discoveredRefs) {
                    String addr = (String)ref.get("referenceAddress");
                    if (!knownAddresses.contains(addr)) {
                        uniqueDiscoveredRefs.add(ref);
                    }
                }

                discoveredRefs = uniqueDiscoveredRefs;
            }

            // Address validation for better error reporting
            Address targetAddress = program.getAddressFactory().getAddress(targetAddressStr);

            result.put("targetAddress", targetAddressStr);
            result.put("targetAddressValid", targetAddress != null);
            result.put("knownReferences", knownRefs);
            result.put("knownReferenceCount", knownRefs.size());

            if (includeMemoryScan) {
                result.put("discoveredReferences", discoveredRefs);
                result.put("discoveredReferenceCount", discoveredRefs.size());
                result.put("memorySearchCriteria", Map.of(
                        "searchOnlyExecutable", searchOnlyExecutable,
                        "searchOnlyReadable", searchOnlyReadable,
                        "maxResults", maxScanResults
                ));
            }

            result.put("totalReferenceCount", knownRefs.size() + discoveredRefs.size());
            result.put("success", true);

        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
            Msg.error(MemoryCrossReferenceService.class, "Error finding references", e);
        }

        return result;
    }

    /**
     * Get all known references to a target address using Ghidra's ReferenceManager.
     * This is fast and should be the primary method for finding references.
     *
     * @param program The program to search in
     * @param targetAddressStr The target address to find references to (as a string)
     * @param monitor Task monitor for tracking progress (can be null)
     * @return List of references found in Ghidra's reference database
     */
    public List<Map<String, Object>> getKnownReferences(
            Program program,
            String targetAddressStr,
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

            // Set up progress monitoring
            TaskMonitor taskMonitor = monitor != null ? monitor : TaskMonitor.DUMMY;

            // Get the ReferenceManager and all references to the target address
            ReferenceManager refManager = program.getReferenceManager();
            ReferenceIterator refIter = refManager.getReferencesTo(targetAddress);

            Listing listing = program.getListing();

            while (refIter.hasNext() && !taskMonitor.isCancelled()) {
                Reference ref = refIter.next();
                Address fromAddress = ref.getFromAddress();

                // Create result map with reference details
                Map<String, Object> result = new HashMap<>();
                result.put("referenceAddress", fromAddress.toString());
                result.put("targetAddress", targetAddress.toString());
                result.put("referenceType", ref.getReferenceType().toString());
                result.put("isPrimary", ref.isPrimary());
                result.put("isOffsetReference", ref.isOffsetReference());
                result.put("offset", ref.getOperandIndex());

                // Try to get code unit information at the reference address
                CodeUnit codeUnit = listing.getCodeUnitAt(fromAddress);
                if (codeUnit != null) {
                    result.put("codeUnitMnemonic", codeUnit.getMnemonicString());

                    // Get context around the reference
                    try {
                        StringBuilder context = new StringBuilder();
                        // Try to get a few code units before and after the reference
                        for (int i = -2; i <= 2; i++) {
                            // Approximate instruction size - adjust if needed for different architectures
                            int instructionSizeGuess = codeUnit.getLength();
                            Address contextAddr = fromAddress.add(i * (long) instructionSizeGuess);
                            if (program.getMemory().contains(contextAddr)) {
                                CodeUnit cu = listing.getCodeUnitAt(contextAddr);
                                if (cu != null) {
                                    if (fromAddress.equals(contextAddr)) { // Highlight the actual reference line
                                        context.append(" --> ");
                                    } else {
                                        context.append("     ");
                                    }
                                    context.append(contextAddr).append(": ").append(cu).append("\n");
                                }
                            }
                        }
                        result.put("context", context.toString().trim());
                    } catch (Exception e) {
                        // If we can't get the context, just continue
                        result.put("context", "[Context unavailable]");
                        Msg.debug(MemoryCrossReferenceService.class, "Could not get context for reference at " + fromAddress, e);
                    }
                }

                // Get block information
                MemoryBlock block = program.getMemory().getBlock(fromAddress);
                if (block != null) {
                    result.put("blockName", block.getName());
                    result.put("blockPermissions", String.format("%s%s%s",
                            block.isRead() ? "r" : "-",
                            block.isWrite() ? "w" : "-",
                            block.isExecute() ? "x" : "-"));
                }

                results.add(result);
            }

            return results;

        } catch (Exception e) {
            Msg.error(MemoryCrossReferenceService.class, "Error finding known references for " + targetAddressStr, e);
            return results; // Return whatever was found so far
        }
    }

    /**
     * Find potential references to a target address by scanning memory.
     * This can find references not tracked by Ghidra, but is much slower and may produce false positives.
     *
     * @param program The program to search in
     * @param targetAddressStr The target address to find references to (as a string)
     * @param searchOnlyExecutable Whether to search only in executable memory
     * @param searchOnlyReadable Whether to search only in readable memory
     * @param maxResults Maximum number of results to return (0 for unlimited)
     * @param monitor Task monitor for tracking progress (can be null)
     * @return List of addresses where potential references were found
     */
    public List<Map<String, Object>> findPotentialReferences(
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
                Msg.info(MemoryCrossReferenceService.class, "No memory blocks match search criteria.");
                return results; // No blocks to search
            }

            // Get pointer size based on program architecture
            int pointerSize = program.getDefaultPointerSize(); // Use default pointer size
            boolean isBigEndian = program.getLanguage().isBigEndian();

            // Set up progress monitoring
            TaskMonitor taskMonitor = monitor != null ? monitor : TaskMonitor.DUMMY;
            long totalBytes = getAddressSetSize(searchSet);
            taskMonitor.initialize(totalBytes, "Scanning memory for references to " + targetAddressStr);
            long bytesSearched = 0;
            int resultCount = 0;

            // Get listing for code unit information
            Listing listing = program.getListing();

            // Search through each memory range
            for (AddressRange range : searchSet) {
                if (taskMonitor.isCancelled()) {
                    break;
                }
                Address start = range.getMinAddress();
                Address end = range.getMaxAddress();
                taskMonitor.setMessage("Scanning " + start + " - " + end);

                // Search in chunks to avoid memory issues with large blocks
                final int CHUNK_SIZE = 1024 * 1024; // 1MB chunks
                Address currentStart = start;

                while (currentStart.compareTo(end) <= 0 && !taskMonitor.isCancelled()) {
                    // Calculate end of current chunk
                    long remainingInChunk = end.subtract(currentStart) + 1; // +1 because end is inclusive
                    long currentChunkSize = Math.min(remainingInChunk, CHUNK_SIZE);
                    Address chunkEndAddress = currentStart.add(currentChunkSize - 1); // Address of the last byte

                    // Read memory chunk
                    byte[] buffer = new byte[(int) currentChunkSize]; // Safe cast as chunkSize <= CHUNK_SIZE

                    try {
                        int bytesRead = memory.getBytes(currentStart, buffer);
                        if (bytesRead != currentChunkSize) {
                            Msg.warn(MemoryCrossReferenceService.class,
                                    "Could not read full chunk at " + currentStart + ". Expected " + currentChunkSize + ", got " + bytesRead);
                            // Adjust buffer if partial read occurred (though getBytes usually throws)
                            if (bytesRead <= 0) {
                                // Skip this chunk if nothing was read
                                bytesSearched += currentChunkSize;
                                taskMonitor.setProgress(bytesSearched);
                                currentStart = chunkEndAddress.add(1);
                                continue;
                            }
                            byte[] actualBuffer = new byte[bytesRead];
                            System.arraycopy(buffer, 0, actualBuffer, 0, bytesRead);
                            buffer = actualBuffer; // Use the actually read buffer
                        }
                    } catch (MemoryAccessException e) {
                        // Skip this chunk if we can't read it
                        Msg.warn(MemoryCrossReferenceService.class,
                                "Could not read memory at " + currentStart + ": " + e.getMessage());
                        bytesSearched += currentChunkSize;
                        taskMonitor.setProgress(bytesSearched);
                        currentStart = chunkEndAddress.add(1);
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
                        result.put("discovered", true); // Mark as discovered by memory scan

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
                                result.put("referenceType", "CODE"); // Could be instruction or data in code
                            }
                        }

                        // Try to get code unit information if it exists at the found address
                        CodeUnit codeUnit = listing.getCodeUnitContaining(refAddress); // Use containing for data refs
                        if (codeUnit != null) {
                            // Check if the found address is the start of the code unit
                            if (codeUnit.getMinAddress().equals(refAddress)) {
                                result.put("codeUnitMnemonic", codeUnit.getMnemonicString());
                                result.put("codeUnitString", codeUnit.toString());
                            } else {
                                // The reference is likely within data defined by a code unit
                                result.put("containingCodeUnit", codeUnit.toString());
                            }
                        }

                        // Get context around the reference (bytes)
                        try {
                            int contextSize = pointerSize * 4; // Show context bytes around the pointer
                            int contextStartOffset = Math.max(0, offset - (contextSize / 2));
                            int contextEndOffset = Math.min(buffer.length, offset + pointerSize + (contextSize / 2));
                            int readSize = contextEndOffset - contextStartOffset;

                            byte[] contextBytes = new byte[readSize];
                            System.arraycopy(buffer, contextStartOffset, contextBytes, 0, readSize);

                            // Format as hex with highlight
                            StringBuilder hexContext = new StringBuilder();
                            int highlightStart = offset - contextStartOffset;
                            int highlightEnd = highlightStart + pointerSize;

                            for (int i = 0; i < readSize; i++) {
                                if (i == highlightStart) hexContext.append("[");
                                hexContext.append(String.format("%02X", contextBytes[i] & 0xFF));
                                if (i == highlightEnd - 1) hexContext.append("]");
                                if (i < readSize - 1) hexContext.append(" ");
                            }
                            result.put("context", hexContext.toString());
                        } catch (Exception e) {
                            Msg.debug(MemoryCrossReferenceService.class, "Failed to get byte context", e);
                            result.put("context", "[Byte context unavailable]");
                        }

                        results.add(result);
                        resultCount++;

                        // Check if we've reached the maximum results
                        if (maxResults > 0 && resultCount >= maxResults) {
                            Msg.info(MemoryCrossReferenceService.class, "Reached maximum results limit (" + maxResults + ").");
                            return results;
                        }
                    }

                    // Update progress
                    bytesSearched += buffer.length; // Use actual buffer length read
                    taskMonitor.setProgress(bytesSearched);

                    // Move to next chunk start address
                    currentStart = chunkEndAddress.add(1);
                }
            }

            taskMonitor.setMessage("Memory scan complete.");
            return results;

        } catch (Exception e) {
            Msg.error(MemoryCrossReferenceService.class, "Error finding potential references for " + targetAddressStr, e);
            return results; // Return whatever was found so far
        }
    }

    /**
     * Helper method to calculate the total size of an AddressSet.
     */
    private long getAddressSetSize(AddressSet set) {
        long size = 0;
        for (AddressRange range : set) {
            size += range.getLength();
        }
        return size;
    }


    /**
     * Searches a byte buffer for occurrences of a specific address value.
     *
     * @param buffer      The byte buffer to search.
     * @param addressValue The address value (as a long) to search for.
     * @param pointerSize The size of a pointer/address in bytes (e.g., 4 for 32-bit, 8 for 64-bit).
     * @param isBigEndian True if the memory layout is big-endian, false for little-endian.
     * @return A list of integer offsets within the buffer where the address value was found.
     */
    private List<Integer> findAddressReferences(
            byte[] buffer,
            long addressValue,
            int pointerSize,
            boolean isBigEndian) {

        List<Integer> offsets = new ArrayList<>();
        ByteBuffer byteBuffer = ByteBuffer.wrap(buffer);

        // Set byte order based on architecture
        byteBuffer.order(isBigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);

        // Iterate through the buffer, checking every possible alignment for the pointer
        for (int i = 0; i <= buffer.length - pointerSize; i++) {
            long currentValue;
            // Read the value at the current offset based on pointer size
            try {
                if (pointerSize == 4) {
                    // Read as unsigned 32-bit integer, store in long
                    currentValue = Integer.toUnsignedLong(byteBuffer.getInt(i));
                } else if (pointerSize == 8) {
                    currentValue = byteBuffer.getLong(i);
                } else {
                    // Skip if pointer size is unexpected (could add support for other sizes if needed)
                    continue;
                }

                // Compare with the target address value
                if (currentValue == addressValue) {
                    offsets.add(i);
                }
            } catch (IndexOutOfBoundsException e) {
                // Should not happen with the loop condition, but good practice
                Msg.warn(MemoryCrossReferenceService.class, "Index out of bounds during buffer scan at offset " + i);
                break; // Stop searching this buffer if bounds error occurs
            }
        }
        return offsets;
    }
}
