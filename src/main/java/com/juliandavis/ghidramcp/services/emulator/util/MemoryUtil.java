package com.juliandavis.ghidramcp.services.emulator.util;

import ghidra.program.model.address.Address;

import java.util.*;

/**
 * Utility class for memory operations in the emulator.
 */
public class MemoryUtil {

    /**
     * Groups contiguous memory writes into byte arrays.
     * 
     * @param memoryWrites Map of individual memory writes
     * @return Map of starting addresses to byte arrays
     */
    public static SortedMap<Address, byte[]> groupContiguousWrites(Map<Address, Byte> memoryWrites) {
        TreeMap<Address, byte[]> result = new TreeMap<>();
        
        if (memoryWrites.isEmpty()) {
            return result;
        }
        
        // Sort addresses
        List<Address> addresses = new ArrayList<>(memoryWrites.keySet());
        Collections.sort(addresses);
        
        Address startAddress = addresses.get(0);
        List<Byte> currentGroup = new ArrayList<>();
        currentGroup.add(memoryWrites.get(startAddress));
        
        for (int i = 1; i < addresses.size(); i++) {
            Address prevAddr = addresses.get(i-1);
            Address currAddr = addresses.get(i);
            
            // Check if addresses are contiguous
            if (currAddr.equals(prevAddr.add(1))) {
                // Continue current group
                currentGroup.add(memoryWrites.get(currAddr));
            } else {
                // Finish current group and start a new one
                byte[] bytes = new byte[currentGroup.size()];
                for (int j = 0; j < currentGroup.size(); j++) {
                    bytes[j] = currentGroup.get(j);
                }
                result.put(startAddress, bytes);
                
                // Start new group
                startAddress = currAddr;
                currentGroup.clear();
                currentGroup.add(memoryWrites.get(currAddr));
            }
        }
        
        // Add the last group
        if (!currentGroup.isEmpty()) {
            byte[] bytes = new byte[currentGroup.size()];
            for (int j = 0; j < currentGroup.size(); j++) {
                bytes[j] = currentGroup.get(j);
            }
            result.put(startAddress, bytes);
        }
        
        return result;
    }
    
    /**
     * Creates memory write info map from address and byte data.
     * 
     * @param entry The entry containing address and byte data
     * @param isBigEndian Whether the architecture is big-endian
     * @return Map containing memory write information
     */
    public static Map<String, Object> createMemoryWriteInfo(Map.Entry<Address, byte[]> entry, boolean isBigEndian) {
        Address addr = entry.getKey();
        byte[] bytes = entry.getValue();
        
        Map<String, Object> writeInfo = new HashMap<>();
        writeInfo.put("address", addr.toString());
        writeInfo.put("length", bytes.length);
        
        // Convert bytes to hex string
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b));
        }
        writeInfo.put("hexValue", hexString.toString());
        
        // Try to interpret as various data types
        if (bytes.length == 1) {
            writeInfo.put("byteValue", bytes[0] & 0xFF);
        } else if (bytes.length == 2) {
            writeInfo.put("shortValue", bytesToShort(bytes, isBigEndian));
        } else if (bytes.length == 4) {
            writeInfo.put("intValue", bytesToInt(bytes, isBigEndian));
            writeInfo.put("floatValue", Float.intBitsToFloat(bytesToInt(bytes, isBigEndian)));
        } else if (bytes.length == 8) {
            writeInfo.put("longValue", bytesToLong(bytes, isBigEndian));
            writeInfo.put("doubleValue", Double.longBitsToDouble(bytesToLong(bytes, isBigEndian)));
        }
        
        // Convert to ASCII representation where possible
        StringBuilder asciiString = new StringBuilder();
        for (byte b : bytes) {
            char c = (char)(b & 0xFF);
            asciiString.append(Character.isISOControl(c) ? '.' : c);
        }
        writeInfo.put("asciiValue", asciiString.toString());
        
        return writeInfo;
    }
    
    /**
     * Converts bytes to a short value.
     * 
     * @param bytes The byte array
     * @param isBigEndian Whether the architecture is big-endian
     * @return The short value
     */
    private static short bytesToShort(byte[] bytes, boolean isBigEndian) {
        if (bytes.length < 2) {
            return 0;
        }
        
        if (isBigEndian) {
            return (short)(((bytes[0] & 0xFF) << 8) | (bytes[1] & 0xFF));
        } else {
            return (short)(((bytes[1] & 0xFF) << 8) | (bytes[0] & 0xFF));
        }
    }
    
    /**
     * Converts bytes to an int value.
     * 
     * @param bytes The byte array
     * @param isBigEndian Whether the architecture is big-endian
     * @return The int value
     */
    private static int bytesToInt(byte[] bytes, boolean isBigEndian) {
        if (bytes.length < 4) {
            return 0;
        }
        
        if (isBigEndian) {
            return ((bytes[0] & 0xFF) << 24) |
                   ((bytes[1] & 0xFF) << 16) |
                   ((bytes[2] & 0xFF) << 8) |
                   (bytes[3] & 0xFF);
        } else {
            return ((bytes[3] & 0xFF) << 24) |
                   ((bytes[2] & 0xFF) << 16) |
                   ((bytes[1] & 0xFF) << 8) |
                   (bytes[0] & 0xFF);
        }
    }
    
    /**
     * Converts bytes to a long value.
     * 
     * @param bytes The byte array
     * @param isBigEndian Whether the architecture is big-endian
     * @return The long value
     */
    private static long bytesToLong(byte[] bytes, boolean isBigEndian) {
        if (bytes.length < 8) {
            return 0;
        }
        
        long result = 0;
        
        if (isBigEndian) {
            for (int i = 0; i < 8; i++) {
                result = (result << 8) | (bytes[i] & 0xFF);
            }
        } else {
            for (int i = 7; i >= 0; i--) {
                result = (result << 8) | (bytes[i] & 0xFF);
            }
        }
        
        return result;
    }
}
