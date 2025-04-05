package com.juliandavis.ghidramcp.services;

import com.juliandavis.ghidramcp.core.service.Service;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;

import java.util.HashMap;
import java.util.Map;

/**
 * A service that provides direct memory access for the current program.
 * This allows for more efficient memory reading without requiring a full emulator session.
 */
public class MemoryReadService implements Service {

    public static final String SERVICE_NAME = "MemoryReadService";
    private Program currentProgram;

    /**
     * Creates a new MemoryReadService.
     */
    public MemoryReadService() {
    }

    @Override
    public String getName() {
        return SERVICE_NAME;
    }

    @Override
    public void initialize(Program program) {
        this.currentProgram = program;
        Msg.info(this, "MemoryReadService initialized with program: " +
                (program != null ? program.getName() : "null"));
    }

    @Override
    public void dispose() {
        this.currentProgram = null;
        Msg.info(this, "MemoryReadService disposed");
    }

    /**
     * Creates a standardized error result.
     *
     * @param errorMessage the error message
     * @param errorCode optional error code
     * @return a standardized error result
     */
    private Map<String, Object> createErrorResult(String errorMessage, int errorCode) {
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
     * Creates a standardized error result with default error code (400).
     *
     * @param errorMessage the error message
     * @return a standardized error result
     */
    private Map<String, Object> createErrorResult(String errorMessage) {
        return createErrorResult(errorMessage, 400);
    }

    /**
     * Creates a standardized success result.
     *
     * @param data the data to include in the response
     * @return a standardized success result
     */
    private Map<String, Object> createSuccessResult(Map<String, Object> data) {
        Map<String, Object> response = new HashMap<>();

        // Standard top-level structure
        response.put("status", "success");
        response.put("data", data);

        return response;
    }

    /**
     * Reads bytes from memory at the specified address.
     *
     * @param addressStr the address to read from
     * @param length the number of bytes to read
     * @return a map containing the memory data
     */
    public Map<String, Object> readMemory(String addressStr, int length) {
        if (currentProgram == null) {
            return createErrorResult("No program is loaded");
        }

        // Limit the number of bytes to read
        int maxLength = 4096;
        if (length > maxLength) {
            return createErrorResult("Requested length exceeds maximum (" + maxLength + " bytes)");
        }

        try {
            // Parse the address
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return createErrorResult("Invalid address: " + addressStr);
            }

            // Get the memory
            Memory memory = currentProgram.getMemory();

            // Check if the address is valid and initialized
            MemoryBlock block = memory.getBlock(addr);
            if (block == null) {
                return createErrorResult("Address is not in any memory block: " + addressStr);
            }

            // Adjust length if it would go beyond the end of the block
            Address blockEnd = block.getEnd();
            Address requestEnd = addr.add(length - 1);
            if (requestEnd.compareTo(blockEnd) > 0) {
                length = (int)addr.subtract(blockEnd) + 1;
                Msg.warn(this, "Adjusted length to " + length + " to fit within memory block");
            }

            // Read the memory
            byte[] bytes = new byte[length];
            try {
                int bytesRead = memory.getBytes(addr, bytes);
                if (bytesRead < length) {
                    return createErrorResult("Could not read all requested bytes");
                }
            } catch (MemoryAccessException e) {
                return createErrorResult("Memory access exception: " + e.getMessage());
            } catch (AddressOutOfBoundsException e) {
                return createErrorResult("Address out of bounds: " + e.getMessage());
            }

            // Convert to hex string
            StringBuilder hex = new StringBuilder();
            for (byte b : bytes) {
                hex.append(String.format("%02x", b));
            }

            // Convert to ASCII string
            StringBuilder ascii = new StringBuilder();
            for (byte b : bytes) {
                ascii.append(isPrintable(b) ? (char) b : '.');
            }

            // Create the data map
            Map<String, Object> data = new HashMap<>();
            data.put("address", addressStr);
            data.put("length", length);
            data.put("hexValue", hex.toString());
            data.put("asciiValue", ascii.toString());

            // Include memory block information for context
            Map<String, Object> blockInfo = new HashMap<>();
            blockInfo.put("name", block.getName());
            blockInfo.put("start", block.getStart().toString());
            blockInfo.put("end", block.getEnd().toString());
            blockInfo.put("size", block.getSize());
            blockInfo.put("permissions", getBlockPermissionsString(block));
            data.put("block", blockInfo);

            return createSuccessResult(data);
        } catch (Exception e) {
            return createErrorResult("Failed to read memory: " + e.getMessage());
        }
    }

    /**
     * Gets a string representation of the memory block permissions.
     *
     * @param block the memory block
     * @return a string with read, write, execute permissions
     */
    private String getBlockPermissionsString(MemoryBlock block) {
        return (block.isRead() ? "r" : "-") +
                (block.isWrite() ? "w" : "-") +
                (block.isExecute() ? "x" : "-");
    }

    /**
     * Checks if a byte is a printable ASCII character.
     *
     * @param b the byte to check
     * @return true if printable, false otherwise
     */
    private boolean isPrintable(byte b) {
        return b >= 32 && b < 127;
    }

    /**
     * Lists all memory blocks in the program.
     *
     * @return a map containing information about all memory blocks
     */
    public Map<String, Object> listMemoryBlocks() {
        if (currentProgram == null) {
            return createErrorResult("No program is loaded");
        }

        try {
            Memory memory = currentProgram.getMemory();
            MemoryBlock[] blocks = memory.getBlocks();

            Map<String, Object>[] blockInfos = new Map[blocks.length];

            for (int i = 0; i < blocks.length; i++) {
                MemoryBlock block = blocks[i];
                Map<String, Object> blockInfo = new HashMap<>();
                blockInfo.put("name", block.getName());
                blockInfo.put("start", block.getStart().toString());
                blockInfo.put("end", block.getEnd().toString());
                blockInfo.put("size", block.getSize());
                blockInfo.put("permissions", getBlockPermissionsString(block));
                blockInfo.put("initialized", block.isInitialized());
                blockInfos[i] = blockInfo;
            }

            Map<String, Object> data = new HashMap<>();
            data.put("blocks", blockInfos);
            data.put("count", blocks.length);
            data.put("totalSize", memory.getSize());

            return createSuccessResult(data);
        } catch (Exception e) {
            return createErrorResult("Failed to list memory blocks: " + e.getMessage());
        }
    }

    /**
     * Gets information about a memory block containing the specified address.
     *
     * @param addressStr the address to query
     * @return a map containing information about the memory block
     */
    public Map<String, Object> getMemoryBlockInfo(String addressStr) {
        if (currentProgram == null) {
            return createErrorResult("No program is loaded");
        }

        try {
            // Parse the address
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return createErrorResult("Invalid address: " + addressStr);
            }

            // Get the memory block
            Memory memory = currentProgram.getMemory();
            MemoryBlock block = memory.getBlock(addr);

            if (block == null) {
                return createErrorResult("Address is not in any memory block: " + addressStr);
            }

            Map<String, Object> blockInfo = new HashMap<>();
            blockInfo.put("name", block.getName());
            blockInfo.put("start", block.getStart().toString());
            blockInfo.put("end", block.getEnd().toString());
            blockInfo.put("size", block.getSize());
            blockInfo.put("permissions", getBlockPermissionsString(block));
            blockInfo.put("initialized", block.isInitialized());
            blockInfo.put("source", block.getSourceName());

            Map<String, Object> data = new HashMap<>();
            data.put("block", blockInfo);
            data.put("address", addressStr);

            return createSuccessResult(data);
        } catch (Exception e) {
            return createErrorResult("Failed to get memory block info: " + e.getMessage());
        }
    }

    /**
     * Checks if an address is valid and initialized in the program's memory.
     *
     * @param addressStr the address to check
     * @return a map containing the result of the check
     */
    public Map<String, Object> isAddressValid(String addressStr) {
        if (currentProgram == null) {
            return createErrorResult("No program is loaded");
        }

        try {
            // Parse the address
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return createErrorResult("Invalid address format: " + addressStr);
            }

            // Get the memory
            Memory memory = currentProgram.getMemory();
            boolean valid = memory.contains(addr);
            boolean initialized = valid && memory.getBlock(addr).isInitialized();

            Map<String, Object> data = new HashMap<>();
            data.put("address", addressStr);
            data.put("valid", valid);
            data.put("initialized", initialized);

            if (valid) {
                MemoryBlock block = memory.getBlock(addr);
                data.put("blockName", block.getName());
            }

            return createSuccessResult(data);
        } catch (Exception e) {
            return createErrorResult("Failed to check address validity: " + e.getMessage());
        }
    }

    /**
     * Gets the address space information for the program.
     *
     * @return a map containing information about all address spaces
     */
    public Map<String, Object> getAddressSpaces() {
        if (currentProgram == null) {
            return createErrorResult("No program is loaded");
        }

        try {
            AddressSpace[] spaces = currentProgram.getAddressFactory().getAllAddressSpaces();
            Map<String, Object>[] spaceInfos = new Map[spaces.length];

            for (int i = 0; i < spaces.length; i++) {
                AddressSpace space = spaces[i];
                Map<String, Object> spaceInfo = new HashMap<>();
                spaceInfo.put("name", space.getName());
                spaceInfo.put("type", getAddressSpaceTypeName(space.getType()));
                spaceInfo.put("typeValue", space.getType());
                spaceInfo.put("size", space.getSize());
                spaceInfo.put("addressableUnitSize", space.getAddressableUnitSize());
                spaceInfo.put("pointerSize", space.getPointerSize());
                spaceInfo.put("maxAddress", space.getMaxAddress().toString());
                spaceInfo.put("minAddress", space.getMinAddress().toString());
                spaceInfos[i] = spaceInfo;
            }

            Map<String, Object> data = new HashMap<>();
            data.put("spaces", spaceInfos);
            data.put("count", spaces.length);
            data.put("defaultSpace", currentProgram.getAddressFactory().getDefaultAddressSpace().getName());

            return createSuccessResult(data);
        } catch (Exception e) {
            return createErrorResult("Failed to get address spaces: " + e.getMessage());
        }
    }

    /**
     * Converts an AddressSpace type integer to a descriptive string.
     *
     * @param type the AddressSpace type integer
     * @return a string representation of the type
     */
    private String getAddressSpaceTypeName(int type) {
        return switch (type) {
            case AddressSpace.TYPE_RAM -> "RAM";
            case AddressSpace.TYPE_REGISTER -> "Register";
            case AddressSpace.TYPE_STACK -> "Stack";
            case AddressSpace.TYPE_CONSTANT -> "Constant";
            case AddressSpace.TYPE_CODE -> "Code";
            case AddressSpace.TYPE_EXTERNAL -> "External";
            case AddressSpace.TYPE_OTHER -> "Other";
            case AddressSpace.TYPE_UNIQUE -> "Unique";
            case AddressSpace.TYPE_VARIABLE -> "Variable";
            case AddressSpace.TYPE_JOIN -> "Join";
            case AddressSpace.TYPE_SYMBOL -> "Symbol";
            case AddressSpace.TYPE_DELETED -> "Deleted";
            case AddressSpace.TYPE_NONE -> "None";
            case AddressSpace.TYPE_UNKNOWN -> "Unknown";
            default -> "Undefined(" + type + ")";
        };
    }
}