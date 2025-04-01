package com.juliandavis.ghidramcp.services.emulator.operations;

import com.juliandavis.ghidramcp.emulation.arch.ArchitectureHelper;
import com.juliandavis.ghidramcp.services.emulator.session.EmulatorSession;
import com.juliandavis.ghidramcp.services.emulator.util.MemoryUtil;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.Register;
import ghidra.util.Msg;

import java.math.BigInteger;
import java.util.*;

/**
 * Utility class for emulator operations.
 * Contains the actual implementation of all emulator-related functions.
 */
public class EmulatorOperations {

    /**
     * Steps the emulator forward by a single instruction.
     * 
     * @param session The emulator session
     * @return Map containing the result status and new program counter state
     */
    public static Map<String, Object> stepEmulator(EmulatorSession session) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            Map<String, Object> registerState = new HashMap<>();
            
            // Get all register values
            for (Register reg : emulator.getProgram().getLanguage().getRegisters()) {
                try {
                    String regName = reg.getName();
                    BigInteger value = emulator.readRegister(regName);
                    registerState.put(regName, value.toString(16));
                } catch (Exception e) {
                    // Skip registers that can't be read
                }
            }
            
            // Get PC as a special case for convenience
            String pcRegisterName = emulator.getPCRegister().getName();
            BigInteger pcValue = emulator.readRegister(pcRegisterName);
            Address pcAddress = session.getProgram().getAddressFactory().getAddress(pcValue.toString(16));
            
            // Extract memory state (focusing on modified memory)
            Map<String, Object> memoryState = new HashMap<>();
            if (!session.getMemoryWrites().isEmpty()) {
                // Group contiguous memory writes
                SortedMap<Address, byte[]> contiguousWrites = MemoryUtil.groupContiguousWrites(session.getMemoryWrites());
                
                for (Map.Entry<Address, byte[]> entry : contiguousWrites.entrySet()) {
                    Address addr = entry.getKey();
                    byte[] bytes = entry.getValue();
                    
                    StringBuilder hexString = new StringBuilder();
                    for (byte b : bytes) {
                        hexString.append(String.format("%02x", b));
                    }
                    
                    memoryState.put(addr.toString(), hexString.toString());
                }
            }
            
            result.put("success", true);
            result.put("registers", registerState);
            result.put("programCounter", pcAddress.toString());
            result.put("memory", memoryState);
            result.put("status", session.isRunning() ? "running" : "stopped");
            
            if (session.getLastError() != null) {
                result.put("lastError", session.getLastError());
            }
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error getting emulator state", e);
            result.put("success", false);
            result.put("error", "Error getting emulator state: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Gets a list of memory locations that were written during emulation.
     * 
     * @param session The emulator session
     * @return Map containing memory write information
     */
    public static Map<String, Object> getMemoryWrites(EmulatorSession session) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            // Get the memory writes
            Map<Address, Byte> memoryWrites = session.getMemoryWrites();
            
            // Group contiguous writes for more efficient representation
            SortedMap<Address, byte[]> contiguousWrites = MemoryUtil.groupContiguousWrites(memoryWrites);
            
            List<Map<String, Object>> writesInfo = new ArrayList<>();
            ArchitectureHelper archHelper = new ArchitectureHelper(session.getProgram(), session.getEmulator());
            boolean isBigEndian = archHelper.isBigEndian();
            
            for (Map.Entry<Address, byte[]> entry : contiguousWrites.entrySet()) {
                writesInfo.add(MemoryUtil.createMemoryWriteInfo(entry, isBigEndian));
            }
            
            result.put("success", true);
            result.put("writes", writesInfo);
            result.put("count", writesInfo.size());
            result.put("totalBytes", memoryWrites.size());
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error getting memory writes", e);
            result.put("success", false);
            result.put("error", "Error getting memory writes: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Gets a list of memory locations that were read during emulation.
     * 
     * @param session The emulator session
     * @return Map containing memory read information
     */
    public static Map<String, Object> getMemoryReads(EmulatorSession session) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            // Get the memory reads
            Map<Address, Byte> memoryReads = session.getMemoryReads();
            
            // Group contiguous reads for more efficient representation
            SortedMap<Address, byte[]> contiguousReads = MemoryUtil.groupContiguousWrites(memoryReads);
            
            List<Map<String, Object>> readsInfo = new ArrayList<>();
            ArchitectureHelper archHelper = new ArchitectureHelper(session.getProgram(), session.getEmulator());
            boolean isBigEndian = archHelper.isBigEndian();
            
            for (Map.Entry<Address, byte[]> entry : contiguousReads.entrySet()) {
                readsInfo.add(MemoryUtil.createMemoryWriteInfo(entry, isBigEndian));
            }
            
            result.put("success", true);
            result.put("reads", readsInfo);
            result.put("count", readsInfo.size());
            result.put("totalBytes", memoryReads.size());
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error getting memory reads", e);
            result.put("success", false);
            result.put("error", "Error getting memory reads: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Reads bytes from the specified memory address.
     * 
     * @param session The emulator session
     * @param addressStr The address to read from
     * @param length The number of bytes to read
     * @return Map containing the memory data
     */
    public static Map<String, Object> readMemory(EmulatorSession session, String addressStr, int length) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            Program program = session.getProgram();
            
            // Parse address
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                result.put("success", false);
                result.put("error", "Invalid address: " + addressStr);
                return result;
            }
            
            // Limit the maximum number of bytes to read
            int maxLength = 4096;
            if (length > maxLength) {
                length = maxLength;
            }
            
            // Read the memory
            byte[] bytes = new byte[length];
            boolean success = emulator.readMemory(address, bytes);
            
            if (!success) {
                result.put("success", false);
                result.put("error", "Failed to read memory from address: " + addressStr);
                return result;
            }
            
            // Track memory read if enabled
            session.trackMemoryRead(address, bytes);
            
            // Convert to hex string
            StringBuilder hexValue = new StringBuilder();
            for (byte b : bytes) {
                hexValue.append(String.format("%02x", b));
            }
            
            // Convert to ASCII representation
            StringBuilder asciiValue = new StringBuilder();
            for (byte b : bytes) {
                asciiValue.append(isPrintableAscii(b) ? (char) b : '.');
            }
            
            result.put("success", true);
            result.put("address", addressStr);
            result.put("length", length);
            result.put("hexValue", hexValue.toString());
            result.put("asciiValue", asciiValue.toString());
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error reading memory", e);
            result.put("success", false);
            result.put("error", "Error reading memory: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Writes bytes to the specified memory address.
     * 
     * @param session The emulator session
     * @param addressStr The address to write to
     * @param bytesHex The bytes to write as a hex string
     * @return Map containing the result of the operation
     */
    public static Map<String, Object> writeMemory(EmulatorSession session, String addressStr, String bytesHex) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            Program program = session.getProgram();
            
            // Parse address
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                result.put("success", false);
                result.put("error", "Invalid address: " + addressStr);
                return result;
            }
            
            // Parse hex string
            if (bytesHex == null || bytesHex.isEmpty()) {
                result.put("success", false);
                result.put("error", "No bytes provided to write");
                return result;
            }
            
            // Ensure hex string has even length
            if (bytesHex.length() % 2 != 0) {
                bytesHex = "0" + bytesHex;  // Pad with leading zero if needed
            }
            
            // Convert hex string to bytes
            byte[] bytes = new byte[bytesHex.length() / 2];
            for (int i = 0; i < bytes.length; i++) {
                String byteStr = bytesHex.substring(i * 2, i * 2 + 2);
                bytes[i] = (byte) Integer.parseInt(byteStr, 16);
            }
            
            // Write memory
            boolean success = emulator.writeMemory(address, bytes);
            
            if (!success) {
                result.put("success", false);
                result.put("error", "Failed to write memory to address: " + addressStr);
                return result;
            }
            
            // Track memory write
            session.trackMemoryWrite(address, bytes);
            
            result.put("success", true);
            result.put("address", addressStr);
            result.put("bytesWritten", bytes.length);
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error writing memory", e);
            result.put("success", false);
            result.put("error", "Error writing memory: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Runs the emulator until a specified condition is met.
     * 
     * @param session The emulator session
     * @param maxSteps Maximum number of steps to run (to prevent infinite loops)
     * @param stopOnBreakpoint Whether to stop at breakpoints
     * @param stopAddressStr Optional specific address to stop at (can be null)
     * @return Map containing the result of the run operation
     */
    public static Map<String, Object> runEmulator(EmulatorSession session, int maxSteps, 
                                               boolean stopOnBreakpoint, String stopAddressStr) {
        Map<String, Object> result = new HashMap<>();
        List<Map<String, Object>> executedInstructions = new ArrayList<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            Map<String, Object> registerState = new HashMap<>();
            
            // Get all register values
            for (Register reg : emulator.getProgram().getLanguage().getRegisters()) {
                try {
                    String regName = reg.getName();
                    BigInteger value = emulator.readRegister(regName);
                    registerState.put(regName, value.toString(16));
                } catch (Exception e) {
                    // Skip registers that can't be read
                }
            }
            
            // Get PC as a special case for convenience
            String pcRegisterName = emulator.getPCRegister().getName();
            BigInteger pcValue = emulator.readRegister(pcRegisterName);
            Address pcAddress = session.getProgram().getAddressFactory().getAddress(pcValue.toString(16));
            
            // Extract memory state (focusing on modified memory)
            Map<String, Object> memoryState = new HashMap<>();
            if (!session.getMemoryWrites().isEmpty()) {
                // Group contiguous memory writes
                SortedMap<Address, byte[]> contiguousWrites = MemoryUtil.groupContiguousWrites(session.getMemoryWrites());
                
                for (Map.Entry<Address, byte[]> entry : contiguousWrites.entrySet()) {
                    Address addr = entry.getKey();
                    byte[] bytes = entry.getValue();
                    
                    StringBuilder hexString = new StringBuilder();
                    for (byte b : bytes) {
                        hexString.append(String.format("%02x", b));
                    }
                    
                    memoryState.put(addr.toString(), hexString.toString());
                }
            }
            
            result.put("success", true);
            result.put("registers", registerState);
            result.put("programCounter", pcAddress.toString());
            result.put("memory", memoryState);
            result.put("status", session.isRunning() ? "running" : "stopped");
            
            if (session.getLastError() != null) {
                result.put("lastError", session.getLastError());
            }
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error getting emulator state", e);
            result.put("success", false);
            result.put("error", "Error getting emulator state: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Gets a list of memory locations that were written during emulation.
     * 
     * @param session The emulator session
     * @return Map containing memory write information
     */
    public static Map<String, Object> getMemoryWrites(EmulatorSession session) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            // Get the memory writes
            Map<Address, Byte> memoryWrites = session.getMemoryWrites();
            
            // Group contiguous writes for more efficient representation
            SortedMap<Address, byte[]> contiguousWrites = MemoryUtil.groupContiguousWrites(memoryWrites);
            
            List<Map<String, Object>> writesInfo = new ArrayList<>();
            ArchitectureHelper archHelper = new ArchitectureHelper(session.getProgram(), session.getEmulator());
            boolean isBigEndian = archHelper.isBigEndian();
            
            for (Map.Entry<Address, byte[]> entry : contiguousWrites.entrySet()) {
                writesInfo.add(MemoryUtil.createMemoryWriteInfo(entry, isBigEndian));
            }
            
            result.put("success", true);
            result.put("writes", writesInfo);
            result.put("count", writesInfo.size());
            result.put("totalBytes", memoryWrites.size());
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error getting memory writes", e);
            result.put("success", false);
            result.put("error", "Error getting memory writes: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Gets a list of memory locations that were read during emulation.
     * 
     * @param session The emulator session
     * @return Map containing memory read information
     */
    public static Map<String, Object> getMemoryReads(EmulatorSession session) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            // Get the memory reads
            Map<Address, Byte> memoryReads = session.getMemoryReads();
            
            // Group contiguous reads for more efficient representation
            SortedMap<Address, byte[]> contiguousReads = MemoryUtil.groupContiguousWrites(memoryReads);
            
            List<Map<String, Object>> readsInfo = new ArrayList<>();
            ArchitectureHelper archHelper = new ArchitectureHelper(session.getProgram(), session.getEmulator());
            boolean isBigEndian = archHelper.isBigEndian();
            
            for (Map.Entry<Address, byte[]> entry : contiguousReads.entrySet()) {
                readsInfo.add(MemoryUtil.createMemoryWriteInfo(entry, isBigEndian));
            }
            
            result.put("success", true);
            result.put("reads", readsInfo);
            result.put("count", readsInfo.size());
            result.put("totalBytes", memoryReads.size());
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error getting memory reads", e);
            result.put("success", false);
            result.put("error", "Error getting memory reads: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Reads bytes from the specified memory address.
     * 
     * @param session The emulator session
     * @param addressStr The address to read from
     * @param length The number of bytes to read
     * @return Map containing the memory data
     */
    public static Map<String, Object> readMemory(EmulatorSession session, String addressStr, int length) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            Program program = session.getProgram();
            
            // Parse address
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                result.put("success", false);
                result.put("error", "Invalid address: " + addressStr);
                return result;
            }
            
            // Limit the maximum number of bytes to read
            int maxLength = 4096;
            if (length > maxLength) {
                length = maxLength;
            }
            
            // Read the memory
            byte[] bytes = new byte[length];
            boolean success = emulator.readMemory(address, bytes);
            
            if (!success) {
                result.put("success", false);
                result.put("error", "Failed to read memory from address: " + addressStr);
                return result;
            }
            
            // Track memory read if enabled
            session.trackMemoryRead(address, bytes);
            
            // Convert to hex string
            StringBuilder hexValue = new StringBuilder();
            for (byte b : bytes) {
                hexValue.append(String.format("%02x", b));
            }
            
            // Convert to ASCII representation
            StringBuilder asciiValue = new StringBuilder();
            for (byte b : bytes) {
                asciiValue.append(isPrintableAscii(b) ? (char) b : '.');
            }
            
            result.put("success", true);
            result.put("address", addressStr);
            result.put("length", length);
            result.put("hexValue", hexValue.toString());
            result.put("asciiValue", asciiValue.toString());
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error reading memory", e);
            result.put("success", false);
            result.put("error", "Error reading memory: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Writes bytes to the specified memory address.
     * 
     * @param session The emulator session
     * @param addressStr The address to write to
     * @param bytesHex The bytes to write as a hex string
     * @return Map containing the result of the operation
     */
    public static Map<String, Object> writeMemory(EmulatorSession session, String addressStr, String bytesHex) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            Program program = session.getProgram();
            
            // Parse address
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                result.put("success", false);
                result.put("error", "Invalid address: " + addressStr);
                return result;
            }
            
            // Parse hex string
            if (bytesHex == null || bytesHex.isEmpty()) {
                result.put("success", false);
                result.put("error", "No bytes provided to write");
                return result;
            }
            
            // Ensure hex string has even length
            if (bytesHex.length() % 2 != 0) {
                bytesHex = "0" + bytesHex;  // Pad with leading zero if needed
            }
            
            // Convert hex string to bytes
            byte[] bytes = new byte[bytesHex.length() / 2];
            for (int i = 0; i < bytes.length; i++) {
                String byteStr = bytesHex.substring(i * 2, i * 2 + 2);
                bytes[i] = (byte) Integer.parseInt(byteStr, 16);
            }
            
            // Write memory
            boolean success = emulator.writeMemory(address, bytes);
            
            if (!success) {
                result.put("success", false);
                result.put("error", "Failed to write memory to address: " + addressStr);
                return result;
            }
            
            // Track memory write
            session.trackMemoryWrite(address, bytes);
            
            result.put("success", true);
            result.put("address", addressStr);
            result.put("bytesWritten", bytes.length);
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error writing memory", e);
            result.put("success", false);
            result.put("error", "Error writing memory: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Gets a list of memory locations that were written during emulation.
     * 
     * @param session The emulator session
     * @return Map containing memory write information
     */
    public static Map<String, Object> getMemoryWrites(EmulatorSession session) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            // Get the memory writes
            Map<Address, Byte> memoryWrites = session.getMemoryWrites();
            
            // Group contiguous writes for more efficient representation
            SortedMap<Address, byte[]> contiguousWrites = MemoryUtil.groupContiguousWrites(memoryWrites);
            
            List<Map<String, Object>> writesInfo = new ArrayList<>();
            ArchitectureHelper archHelper = new ArchitectureHelper(session.getProgram(), session.getEmulator());
            boolean isBigEndian = archHelper.isBigEndian();
            
            for (Map.Entry<Address, byte[]> entry : contiguousWrites.entrySet()) {
                writesInfo.add(MemoryUtil.createMemoryWriteInfo(entry, isBigEndian));
            }
            
            result.put("success", true);
            result.put("writes", writesInfo);
            result.put("count", writesInfo.size());
            result.put("totalBytes", memoryWrites.size());
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error getting memory writes", e);
            result.put("success", false);
            result.put("error", "Error getting memory writes: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Gets a list of memory locations that were read during emulation.
     * 
     * @param session The emulator session
     * @return Map containing memory read information
     */
    public static Map<String, Object> getMemoryReads(EmulatorSession session) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            // Get the memory reads
            Map<Address, Byte> memoryReads = session.getMemoryReads();
            
            // Group contiguous reads for more efficient representation
            SortedMap<Address, byte[]> contiguousReads = MemoryUtil.groupContiguousWrites(memoryReads);
            
            List<Map<String, Object>> readsInfo = new ArrayList<>();
            ArchitectureHelper archHelper = new ArchitectureHelper(session.getProgram(), session.getEmulator());
            boolean isBigEndian = archHelper.isBigEndian();
            
            for (Map.Entry<Address, byte[]> entry : contiguousReads.entrySet()) {
                readsInfo.add(MemoryUtil.createMemoryWriteInfo(entry, isBigEndian));
            }
            
            result.put("success", true);
            result.put("reads", readsInfo);
            result.put("count", readsInfo.size());
            result.put("totalBytes", memoryReads.size());
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error getting memory reads", e);
            result.put("success", false);
            result.put("error", "Error getting memory reads: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Reads bytes from the specified memory address.
     * 
     * @param session The emulator session
     * @param addressStr The address to read from
     * @param length The number of bytes to read
     * @return Map containing the memory data
     */
    public static Map<String, Object> readMemory(EmulatorSession session, String addressStr, int length) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            Program program = session.getProgram();
            
            // Parse address
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                result.put("success", false);
                result.put("error", "Invalid address: " + addressStr);
                return result;
            }
            
            // Limit the maximum number of bytes to read
            int maxLength = 4096;
            if (length > maxLength) {
                length = maxLength;
            }
            
            // Read the memory
            byte[] bytes = new byte[length];
            boolean success = emulator.readMemory(address, bytes);
            
            if (!success) {
                result.put("success", false);
                result.put("error", "Failed to read memory from address: " + addressStr);
                return result;
            }
            
            // Track memory read if enabled
            session.trackMemoryRead(address, bytes);
            
            // Convert to hex string
            StringBuilder hexValue = new StringBuilder();
            for (byte b : bytes) {
                hexValue.append(String.format("%02x", b));
            }
            
            // Convert to ASCII representation
            StringBuilder asciiValue = new StringBuilder();
            for (byte b : bytes) {
                asciiValue.append(isPrintableAscii(b) ? (char) b : '.');
            }
            
            result.put("success", true);
            result.put("address", addressStr);
            result.put("length", length);
            result.put("hexValue", hexValue.toString());
            result.put("asciiValue", asciiValue.toString());
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error reading memory", e);
            result.put("success", false);
            result.put("error", "Error reading memory: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Writes bytes to the specified memory address.
     * 
     * @param session The emulator session
     * @param addressStr The address to write to
     * @param bytesHex The bytes to write as a hex string
     * @return Map containing the result of the operation
     */
    public static Map<String, Object> writeMemory(EmulatorSession session, String addressStr, String bytesHex) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            Program program = session.getProgram();
            
            // Parse address
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                result.put("success", false);
                result.put("error", "Invalid address: " + addressStr);
                return result;
            }
            
            // Parse hex string
            if (bytesHex == null || bytesHex.isEmpty()) {
                result.put("success", false);
                result.put("error", "No bytes provided to write");
                return result;
            }
            
            // Ensure hex string has even length
            if (bytesHex.length() % 2 != 0) {
                bytesHex = "0" + bytesHex;  // Pad with leading zero if needed
            }
            
            // Convert hex string to bytes
            byte[] bytes = new byte[bytesHex.length() / 2];
            for (int i = 0; i < bytes.length; i++) {
                String byteStr = bytesHex.substring(i * 2, i * 2 + 2);
                bytes[i] = (byte) Integer.parseInt(byteStr, 16);
            }
            
            // Write memory
            boolean success = emulator.writeMemory(address, bytes);
            
            if (!success) {
                result.put("success", false);
                result.put("error", "Failed to write memory to address: " + addressStr);
                return result;
            }
            
            // Track memory write
            session.trackMemoryWrite(address, bytes);
            
            result.put("success", true);
            result.put("address", addressStr);
            result.put("bytesWritten", bytes.length);
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error writing memory", e);
            result.put("success", false);
            result.put("error", "Error writing memory: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Checks if a byte is a printable ASCII character.
     * 
     * @param b The byte to check
     * @return true if printable, false otherwise
     */
    private static boolean isPrintableAscii(byte b) {
        return b >= 32 && b < 127; // Printable ASCII range
    }
    
    /**
     * Get all conditional breakpoints.
     * 
     * @param session The emulator session
     * @return Map containing conditional breakpoint information
     */
    public static Map<String, Object> getConditionalBreakpoints(EmulatorSession session) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            Map<String, Object> registerState = new HashMap<>();
            
            // Get all register values
            for (Register reg : emulator.getProgram().getLanguage().getRegisters()) {
                try {
                    String regName = reg.getName();
                    BigInteger value = emulator.readRegister(regName);
                    registerState.put(regName, value.toString(16));
                } catch (Exception e) {
                    // Skip registers that can't be read
                }
            }
            
            // Get PC as a special case for convenience
            String pcRegisterName = emulator.getPCRegister().getName();
            BigInteger pcValue = emulator.readRegister(pcRegisterName);
            Address pcAddress = session.getProgram().getAddressFactory().getAddress(pcValue.toString(16));
            
            // Extract memory state (focusing on modified memory)
            Map<String, Object> memoryState = new HashMap<>();
            if (!session.getMemoryWrites().isEmpty()) {
                // Group contiguous memory writes
                SortedMap<Address, byte[]> contiguousWrites = MemoryUtil.groupContiguousWrites(session.getMemoryWrites());
                
                for (Map.Entry<Address, byte[]> entry : contiguousWrites.entrySet()) {
                    Address addr = entry.getKey();
                    byte[] bytes = entry.getValue();
                    
                    StringBuilder hexString = new StringBuilder();
                    for (byte b : bytes) {
                        hexString.append(String.format("%02x", b));
                    }
                    
                    memoryState.put(addr.toString(), hexString.toString());
                }
            }
            
            result.put("success", true);
            result.put("registers", registerState);
            result.put("programCounter", pcAddress.toString());
            result.put("memory", memoryState);
            result.put("status", session.isRunning() ? "running" : "stopped");
            
            if (session.getLastError() != null) {
                result.put("lastError", session.getLastError());
            }
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error getting emulator state", e);
            result.put("success", false);
            result.put("error", "Error getting emulator state: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Gets a list of memory locations that were written during emulation.
     * 
     * @param session The emulator session
     * @return Map containing memory write information
     */
    public static Map<String, Object> getMemoryWrites(EmulatorSession session) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            // Get the memory writes
            Map<Address, Byte> memoryWrites = session.getMemoryWrites();
            
            // Group contiguous writes for more efficient representation
            SortedMap<Address, byte[]> contiguousWrites = MemoryUtil.groupContiguousWrites(memoryWrites);
            
            List<Map<String, Object>> writesInfo = new ArrayList<>();
            ArchitectureHelper archHelper = new ArchitectureHelper(session.getProgram(), session.getEmulator());
            boolean isBigEndian = archHelper.isBigEndian();
            
            for (Map.Entry<Address, byte[]> entry : contiguousWrites.entrySet()) {
                writesInfo.add(MemoryUtil.createMemoryWriteInfo(entry, isBigEndian));
            }
            
            result.put("success", true);
            result.put("writes", writesInfo);
            result.put("count", writesInfo.size());
            result.put("totalBytes", memoryWrites.size());
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error getting memory writes", e);
            result.put("success", false);
            result.put("error", "Error getting memory writes: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Gets a list of memory locations that were read during emulation.
     * 
     * @param session The emulator session
     * @return Map containing memory read information
     */
    public static Map<String, Object> getMemoryReads(EmulatorSession session) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            // Get the memory reads
            Map<Address, Byte> memoryReads = session.getMemoryReads();
            
            // Group contiguous reads for more efficient representation
            SortedMap<Address, byte[]> contiguousReads = MemoryUtil.groupContiguousWrites(memoryReads);
            
            List<Map<String, Object>> readsInfo = new ArrayList<>();
            ArchitectureHelper archHelper = new ArchitectureHelper(session.getProgram(), session.getEmulator());
            boolean isBigEndian = archHelper.isBigEndian();
            
            for (Map.Entry<Address, byte[]> entry : contiguousReads.entrySet()) {
                readsInfo.add(MemoryUtil.createMemoryWriteInfo(entry, isBigEndian));
            }
            
            result.put("success", true);
            result.put("reads", readsInfo);
            result.put("count", readsInfo.size());
            result.put("totalBytes", memoryReads.size());
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error getting memory reads", e);
            result.put("success", false);
            result.put("error", "Error getting memory reads: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Reads bytes from the specified memory address.
     * 
     * @param session The emulator session
     * @param addressStr The address to read from
     * @param length The number of bytes to read
     * @return Map containing the memory data
     */
    public static Map<String, Object> readMemory(EmulatorSession session, String addressStr, int length) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            Program program = session.getProgram();
            
            // Parse address
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                result.put("success", false);
                result.put("error", "Invalid address: " + addressStr);
                return result;
            }
            
            // Limit the maximum number of bytes to read
            int maxLength = 4096;
            if (length > maxLength) {
                length = maxLength;
            }
            
            // Read the memory
            byte[] bytes = new byte[length];
            boolean success = emulator.readMemory(address, bytes);
            
            if (!success) {
                result.put("success", false);
                result.put("error", "Failed to read memory from address: " + addressStr);
                return result;
            }
            
            // Track memory read if enabled
            session.trackMemoryRead(address, bytes);
            
            // Convert to hex string
            StringBuilder hexValue = new StringBuilder();
            for (byte b : bytes) {
                hexValue.append(String.format("%02x", b));
            }
            
            // Convert to ASCII representation
            StringBuilder asciiValue = new StringBuilder();
            for (byte b : bytes) {
                asciiValue.append(isPrintableAscii(b) ? (char) b : '.');
            }
            
            result.put("success", true);
            result.put("address", addressStr);
            result.put("length", length);
            result.put("hexValue", hexValue.toString());
            result.put("asciiValue", asciiValue.toString());
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error reading memory", e);
            result.put("success", false);
            result.put("error", "Error reading memory: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Writes bytes to the specified memory address.
     * 
     * @param session The emulator session
     * @param addressStr The address to write to
     * @param bytesHex The bytes to write as a hex string
     * @return Map containing the result of the operation
     */
    public static Map<String, Object> writeMemory(EmulatorSession session, String addressStr, String bytesHex) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            Program program = session.getProgram();
            
            // Parse address
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                result.put("success", false);
                result.put("error", "Invalid address: " + addressStr);
                return result;
            }
            
            // Parse hex string
            if (bytesHex == null || bytesHex.isEmpty()) {
                result.put("success", false);
                result.put("error", "No bytes provided to write");
                return result;
            }
            
            // Ensure hex string has even length
            if (bytesHex.length() % 2 != 0) {
                bytesHex = "0" + bytesHex;  // Pad with leading zero if needed
            }
            
            // Convert hex string to bytes
            byte[] bytes = new byte[bytesHex.length() / 2];
            for (int i = 0; i < bytes.length; i++) {
                String byteStr = bytesHex.substring(i * 2, i * 2 + 2);
                bytes[i] = (byte) Integer.parseInt(byteStr, 16);
            }
            
            // Write memory
            boolean success = emulator.writeMemory(address, bytes);
            
            if (!success) {
                result.put("success", false);
                result.put("error", "Failed to write memory to address: " + addressStr);
                return result;
            }
            
            // Track memory write
            session.trackMemoryWrite(address, bytes);
            
            result.put("success", true);
            result.put("address", addressStr);
            result.put("bytesWritten", bytes.length);
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error writing memory", e);
            result.put("success", false);
            result.put("error", "Error writing memory: " + e.getMessage());
            return result;
        }
    }
}
