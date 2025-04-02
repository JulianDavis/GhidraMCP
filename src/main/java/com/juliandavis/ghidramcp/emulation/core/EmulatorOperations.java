package com.juliandavis.ghidramcp.emulation.core;

import com.juliandavis.ghidramcp.emulation.arch.ArchitectureHelper;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.Register;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

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
        
        if (!session.isRunning()) {
            result.put("success", false);
            result.put("error", "Emulator is not running");
            return result;
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            
            // Get architecture helper
            ArchitectureHelper archHelper = new ArchitectureHelper(session.getProgram(), emulator);
            
            // Get the current program counter
            String pcRegisterName = archHelper.getProgramCounterRegisterName();
            Address currentPC = session.getProgram().getAddressFactory().getAddress(
                    emulator.readRegister(pcRegisterName).toString(16));
            
            // Step the emulator
            boolean stepped = emulator.step(TaskMonitor.DUMMY);
            
            // Read the new program counter
            Address newPC = session.getProgram().getAddressFactory().getAddress(
                    emulator.readRegister(pcRegisterName).toString(16));
            
            // Set PC register value for tracking
            session.setStartAddress(newPC);
            
            if (!stepped) {
                session.setRunning(false);
                session.setLastError("Emulator step failed");
                result.put("success", false);
                result.put("error", "Emulator step failed");
                return result;
            }
            
            // Track all register changes
            List<Register> registers = emulator.getProgram().getLanguage().getRegisters();
            for (Register reg : registers) {
                try {
                    String regName = reg.getName();
                    session.trackRegisterWrite(regName, emulator.readRegister(regName).longValue());
                } catch (Exception e) {
                    // Some registers may not be readable; just skip them
                }
            }
            
            // Track stack changes if enabled
            if (session.isTrackingStackChanges()) {
                trackStackChanges(session, currentPC);
            }
            
            result.put("success", true);
            result.put("previousPC", currentPC.toString());
            result.put("newPC", newPC.toString());
            
            // Get the instruction that was executed
            try {
                result.put("instruction", session.getProgram().getListing().getInstructionAt(currentPC).toString());
            } catch (Exception e) {
                result.put("instruction", "Unknown");
            }
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error stepping emulator", e);
            session.setLastError("Error stepping emulator: " + e.getMessage());
            session.setRunning(false);
            result.put("success", false);
            result.put("error", e.getMessage());
            return result;
        }
    }
    
    /**
     * Retrieves the current emulation state.
     * 
     * @param session The emulator session
     * @return Map containing the registers and memory state
     */
    public static Map<String, Object> getEmulatorState(EmulatorSession session) {
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
                SortedMap<Address, byte[]> contiguousWrites = groupContiguousWrites(session.getMemoryWrites());
                
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
     * Groups contiguous memory writes into byte arrays.
     * 
     * @param memoryWrites Map of individual memory writes
     * @return Map of starting addresses to byte arrays
     */
    private static SortedMap<Address, byte[]> groupContiguousWrites(Map<Address, Byte> memoryWrites) {
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
     * Checks if a byte is a printable ASCII character.
     * 
     * @param b The byte to check
     * @return true if printable, false otherwise
     */
    private static boolean isPrintableAscii(byte b) {
        return b >= 32 && b < 127; // Printable ASCII range
    }
    
    /**
     * Creates a map with information about a memory write.
     * 
     * @param entry The memory write entry
     * @param isBigEndian Whether the architecture is big-endian
     * @return Map with information about the memory write
     */
    private static Map<String, Object> createMemoryWriteInfo(Map.Entry<Address, byte[]> entry, boolean isBigEndian) {
        Map<String, Object> info = new HashMap<>();
        Address addr = entry.getKey();
        byte[] bytes = entry.getValue();
        
        info.put("address", addr.toString());
        info.put("length", bytes.length);
        
        // Convert to hex string
        StringBuilder hexValue = new StringBuilder();
        for (byte b : bytes) {
            hexValue.append(String.format("%02x", b));
        }
        info.put("hexValue", hexValue.toString());
        
        // Convert to ASCII representation
        StringBuilder asciiValue = new StringBuilder();
        for (byte b : bytes) {
            asciiValue.append(isPrintableAscii(b) ? (char) b : '.');
        }
        info.put("asciiValue", asciiValue.toString());
        
        return info;
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
            SortedMap<Address, byte[]> contiguousWrites = groupContiguousWrites(memoryWrites);
            
            List<Map<String, Object>> writesInfo = new ArrayList<>();
            ArchitectureHelper archHelper = new ArchitectureHelper(session.getProgram(), session.getEmulator());
            boolean isBigEndian = archHelper.isBigEndian();
            
            for (Map.Entry<Address, byte[]> entry : contiguousWrites.entrySet()) {
                writesInfo.add(createMemoryWriteInfo(entry, isBigEndian));
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
            SortedMap<Address, byte[]> contiguousReads = groupContiguousWrites(memoryReads);
            
            List<Map<String, Object>> readsInfo = new ArrayList<>();
            ArchitectureHelper archHelper = new ArchitectureHelper(session.getProgram(), session.getEmulator());
            boolean isBigEndian = archHelper.isBigEndian();
            
            for (Map.Entry<Address, byte[]> entry : contiguousReads.entrySet()) {
                readsInfo.add(createMemoryWriteInfo(entry, isBigEndian));
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
            
            // The readMemory method returns the number of bytes read, not a boolean success flag
            byte[] bytes = emulator.readMemory(address, length);
            if (bytes == null || bytes.length != length) {
                result.put("success", false);
                result.put("error", "Failed to read expected number of bytes from address: " + addressStr);
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
           emulator.writeMemory(address, bytes);
            
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
     * Set a breakpoint at the specified address.
     * 
     * @param session The emulator session
     * @param addressStr The address to set the breakpoint at (as a string)
     * @return Map containing the result of the operation
     */
    public static Map<String, Object> setBreakpoint(EmulatorSession session, String addressStr) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            Program program = session.getProgram();
            Address address = program.getAddressFactory().getAddress(addressStr);
            
            if (address == null) {
                result.put("success", false);
                result.put("error", "Invalid address: " + addressStr);
                return result;
            }
            
            boolean added = session.addBreakpoint(address);
            
            result.put("success", true);
            result.put("address", address.toString());
            result.put("added", added);
            if (!added) {
                result.put("message", "Breakpoint already exists at this address");
            }
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error setting breakpoint", e);
            result.put("success", false);
            result.put("error", "Error setting breakpoint: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Set a conditional breakpoint at the specified address.
     * 
     * @param session The emulator session
     * @param addressStr The address to set the breakpoint at (as a string)
     * @param condition The condition expression (e.g., "EAX=0x10" or "ECX>5")
     * @return Map containing the result of the operation
     */
    public static Map<String, Object> setConditionalBreakpoint(EmulatorSession session, String addressStr, String condition) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            Program program = session.getProgram();
            Address address = program.getAddressFactory().getAddress(addressStr);
            
            if (address == null) {
                result.put("success", false);
                result.put("error", "Invalid address: " + addressStr);
                return result;
            }
            
            if (condition == null || condition.trim().isEmpty()) {
                result.put("success", false);
                result.put("error", "No condition provided");
                return result;
            }
            
            // Add the breakpoint
            session.addConditionalBreakpoint(address, condition);
            
            // Check if the breakpoint was added by looking for it in the map
            boolean added = session.getConditionalBreakpoints().containsKey(address.toString()) && 
                          session.getConditionalBreakpoints().get(address.toString()).equals(condition);
            
            result.put("success", true);
            result.put("address", address.toString());
            result.put("condition", condition);
            result.put("added", added);
            if (!added) {
                result.put("message", "Conditional breakpoint already exists at this address");
            }
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error setting conditional breakpoint", e);
            result.put("success", false);
            result.put("error", "Error setting conditional breakpoint: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Clear a breakpoint at the specified address.
     * 
     * @param session The emulator session
     * @param addressStr The address to clear the breakpoint from (as a string)
     * @return Map containing the result of the operation
     */
    public static Map<String, Object> clearBreakpoint(EmulatorSession session, String addressStr) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            Program program = session.getProgram();
            Address address = program.getAddressFactory().getAddress(addressStr);
            
            if (address == null) {
                result.put("success", false);
                result.put("error", "Invalid address: " + addressStr);
                return result;
            }
            
            boolean removed = session.removeBreakpoint(address);
            
            result.put("success", true);
            result.put("address", address.toString());
            result.put("removed", removed);
            if (!removed) {
                result.put("message", "No breakpoint exists at this address");
            }
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error clearing breakpoint", e);
            result.put("success", false);
            result.put("error", "Error clearing breakpoint: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Get a list of all active breakpoints.
     * 
     * @param session The emulator session
     * @return Map containing the list of breakpoints
     */
    public static Map<String, Object> getBreakpoints(EmulatorSession session) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            List<String> breakpoints = new ArrayList<>();
            
            for (Address address : session.getBreakpoints()) {
                breakpoints.add(address.toString());
            }
            
            result.put("success", true);
            result.put("breakpoints", breakpoints);
            result.put("count", breakpoints.size());
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error getting breakpoints", e);
            result.put("success", false);
            result.put("error", "Error getting breakpoints: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Get a list of all conditional breakpoints.
     * 
     * @param session The emulator session
     * @return Map containing the list of conditional breakpoints
     */
    public static Map<String, Object> getConditionalBreakpoints(EmulatorSession session) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            List<Map<String, Object>> breakpoints = new ArrayList<>();
            
            for (Map.Entry<String, String> entry : session.getConditionalBreakpoints().entrySet()) {
                Map<String, Object> bp = new HashMap<>();
                bp.put("address", entry.getKey());
                bp.put("condition", entry.getValue());
                breakpoints.add(bp);
            }
            
            result.put("success", true);
            result.put("conditionalBreakpoints", breakpoints);
            result.put("count", breakpoints.size());
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error getting conditional breakpoints", e);
            result.put("success", false);
            result.put("error", "Error getting conditional breakpoints: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Evaluates a conditional breakpoint expression
     * 
     * @param session The emulator session
     * @param condition The condition expression to evaluate
     * @return true if the condition is met, false otherwise
     */
    private static boolean evaluateBreakpointCondition(EmulatorSession session, String condition) {
        try {
            EmulatorHelper emulator = session.getEmulator();
            
            // Simple condition format: REG=VALUE or REG!=VALUE
            if (condition.contains("=") || condition.contains("!=") || 
                condition.contains("<") || condition.contains(">")) {
                
                // Try to split the condition into register and value
                String operation = null;
                String[] parts = null;
                
                if (condition.contains("!=")) {
                    operation = "!=";
                    parts = condition.split("!=");
                } else if (condition.contains("<=")) {
                    operation = "<=";
                    parts = condition.split("<=");
                } else if (condition.contains(">=")) {
                    operation = ">=";
                    parts = condition.split(">=");
                } else if (condition.contains("=")) {
                    operation = "=";
                    parts = condition.split("=");
                } else if (condition.contains("<")) {
                    operation = "<";
                    parts = condition.split("<");
                } else if (condition.contains(">")) {
                    operation = ">";
                    parts = condition.split(">");
                }
                
                if (parts != null && parts.length == 2) {
                    String regName = parts[0].trim();
                    String valueStr = parts[1].trim();
                    
                    // Handle hex values
                    long compareValue;
                    if (valueStr.startsWith("0x") || valueStr.startsWith("0X")) {
                        compareValue = Long.parseLong(valueStr.substring(2), 16);
                    } else {
                        compareValue = Long.parseLong(valueStr);
                    }
                    
                    // Get register value
                    BigInteger regValue = emulator.readRegister(regName);
                    
                    if (regValue != null) {
                        switch (operation) {
                            case "=":
                                return regValue.longValue() == compareValue;
                            case "!=":
                                return regValue.longValue() != compareValue;
                            case "<":
                                return regValue.longValue() < compareValue;
                            case ">":
                                return regValue.longValue() > compareValue;
                            case "<=":
                                return regValue.longValue() <= compareValue;
                            case ">=":
                                return regValue.longValue() >= compareValue;
                        }
                    }
                }
            }
            
            // Memory conditions: MEM[addr]=value
            if (condition.contains("MEM[") && condition.contains("]=")) {
                int startIdx = condition.indexOf("MEM[") + 4;
                int endIdx = condition.indexOf("]", startIdx);
                
                if (startIdx > 4 && endIdx > startIdx) {
                    String addrStr = condition.substring(startIdx, endIdx).trim();
                    Address addr = session.getProgram().getAddressFactory().getAddress(addrStr);
                    
                    if (addr != null) {
                        // Extract the expected value
                        String valueStr = condition.substring(condition.indexOf("]=") + 2).trim();
                        
                        // Handle hex values
                        long compareValue;
                        if (valueStr.startsWith("0x") || valueStr.startsWith("0X")) {
                            compareValue = Long.parseLong(valueStr.substring(2), 16);
                        } else {
                            compareValue = Long.parseLong(valueStr);
                        }
                        
                        // Read memory value
                        try {
                            byte memValue = emulator.readMemoryByte(addr);
                            return (memValue & 0xFF) == (compareValue & 0xFF);
                        } catch (Exception e) {
                            Msg.warn(EmulatorOperations.class, "Cannot read memory at " + addr + ": " + e.getMessage());
                        }
                    }
                }
            }
            
            return false;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error evaluating breakpoint condition: " + condition, e);
            return false;
        }
    }
    
    /**
     * Tracks stack changes for the current instruction
     * 
     * @param session The emulator session
     * @param instructionAddress The address of the current instruction
     */
    private static void trackStackChanges(EmulatorSession session, Address instructionAddress) {
        try {
            EmulatorHelper emulator = session.getEmulator();
            Program program = session.getProgram();
            
            // Get architecture-specific information
            ArchitectureHelper archHelper = new ArchitectureHelper(program, emulator);
            
            // Get stack growth direction - critical for correct stack analysis
            int stackGrowthDirection = archHelper.getStackGrowthDirection();
            
            // Get stack pointer value using architecture helper
            String spRegName = archHelper.getStackPointerRegisterName();
            if (spRegName == null) {
                Msg.warn(EmulatorOperations.class, "Could not determine stack pointer register");
                return;
            }
            
            BigInteger spValue = emulator.readRegister(spRegName);
            if (spValue == null) {
                return;
            }
            
            // Create stack frame
            Map<String, Object> frame = new HashMap<>();
            frame.put("instruction", instructionAddress.toString());
            frame.put("stackPointer", spValue.toString(16));
            frame.put("register", spRegName);
            frame.put("stackGrowthDirection", stackGrowthDirection);
            frame.put("stackGrowthDirectionDesc", stackGrowthDirection > 0 ? "upward" : "downward");
            
            // Try to read some values from the stack
            Address stackAddr = program.getAddressFactory().getAddress(spValue.toString(16));
            List<Map<String, Object>> stackValues = new ArrayList<>();
            
            // Get pointer size for this architecture
            int pointerSize = archHelper.getPointerSize();
            
            // Read up to 8 stack values, accounting for stack growth direction
            for (int i = 0; i < 8; i++) {
                try {
                    // Address calculation based on stack growth direction
                    // For a downward-growing stack (typical), we look at higher addresses for stack values
                    // For an upward-growing stack, we look at lower addresses for stack values
                    Address valueAddr = stackAddr.add((long) i * pointerSize * stackGrowthDirection);
                    
                    byte[] bytes = new byte[pointerSize];
                    for (int j = 0; j < bytes.length; j++) {
                        bytes[j] = emulator.readMemoryByte(valueAddr.add(j));
                    }
                    
                    Map<String, Object> entry = new HashMap<>();
                    entry.put("offset", i * pointerSize);
                    
                    // Convert to hex string
                    StringBuilder hexValue = new StringBuilder();
                    for (byte b : bytes) {
                        hexValue.append(String.format("%02x", b));
                    }
                    entry.put("value", "0x" + hexValue);
                    
                    // Include the address of this stack value
                    entry.put("address", valueAddr.toString());
                    
                    stackValues.add(entry);
                } catch (Exception e) {
                    // Stop if we can't read more
                    break;
                }
            }
            
            frame.put("values", stackValues);
            
            // Add to stack trace
            session.addStackFrame(frame);
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error tracking stack changes", e);
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
        
        if (!session.isRunning()) {
            result.put("success", false);
            result.put("error", "Emulator is not running");
            return result;
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            Address stopAddress = null;
            
            // Parse stop address if provided
            if (stopAddressStr != null && !stopAddressStr.isEmpty()) {
                stopAddress = session.getProgram().getAddressFactory().getAddress(stopAddressStr);
            }
            
            // Use architecture helper for processor-specific register names
            ArchitectureHelper archHelper = new ArchitectureHelper(session.getProgram(), emulator);
            String pcRegisterName = archHelper.getProgramCounterRegisterName();
            int stepCount = 0;
            boolean hitBreakpoint = false;
            boolean reachedStopAddress = false;
            
            // Execute steps until condition is met
            while (stepCount < maxSteps) {
                // Get current PC before step
                Address currentPC = session.getProgram().getAddressFactory().getAddress(
                        emulator.readRegister(pcRegisterName).toString(16));
                
                // Check for regular breakpoint before stepping
                if (stopOnBreakpoint && session.getBreakpoints().contains(currentPC)) {
                    hitBreakpoint = true;
                    result.put("breakpointType", "normal");
                    break;
                }
                
                // Check for conditional breakpoint before stepping
                if (stopOnBreakpoint && session.getConditionalBreakpoints().containsKey(currentPC.toString())) {
                    String condition = session.getConditionalBreakpoints().get(currentPC.toString());
                    boolean conditionMet = evaluateBreakpointCondition(session, condition);
                    
                    if (conditionMet) {
                        hitBreakpoint = true;
                        result.put("breakpointType", "conditional");
                        result.put("condition", condition);
                        break;
                    }
                }
                
                // Check for stop address before stepping
                if (currentPC.equals(stopAddress)) {
                    reachedStopAddress = true;
                    break;
                }
                
                // Step the emulator
                boolean stepped = emulator.step(TaskMonitor.DUMMY);
                
                // Read the new program counter
                Address newPC = session.getProgram().getAddressFactory().getAddress(
                        emulator.readRegister(pcRegisterName).toString(16));
                
                // Track the new PC
                session.setStartAddress(newPC);
                
                if (!stepped) {
                    session.setLastError("Emulator step failed during run at step " + stepCount);
                    result.put("success", false);
                    result.put("error", "Emulator step failed during run at step " + stepCount);
                    result.put("stepsExecuted", stepCount);
                    result.put("executedInstructions", executedInstructions);
                    return result;
                }
                
                // Track register changes
                List<Register> registers = emulator.getProgram().getLanguage().getRegisters();
                for (Register reg : registers) {
                    try {
                        String regName = reg.getName();
                        session.trackRegisterWrite(regName, emulator.readRegister(regName).longValue());
                    } catch (Exception e) {
                        // Some registers may not be readable; just skip them
                    }
                }
                
                // Track stack changes if enabled
                if (session.isTrackingStackChanges()) {
                    trackStackChanges(session, currentPC);
                }
                
                // Record executed instruction
                Map<String, Object> instrInfo = new HashMap<>();
                instrInfo.put("address", currentPC.toString());
                try {
                    instrInfo.put("instruction", session.getProgram().getListing().getInstructionAt(currentPC).toString());
                } catch (Exception e) {
                    instrInfo.put("instruction", "Unknown");
                }
                executedInstructions.add(instrInfo);
                
                stepCount++;
            }
            
            result.put("success", true);
            result.put("stepsExecuted", stepCount);
            result.put("executedInstructions", executedInstructions);
            
            // Get the current PC
            Address currentPC = session.getProgram().getAddressFactory().getAddress(
                    emulator.readRegister(pcRegisterName).toString(16));
            result.put("currentPC", currentPC.toString());
            
            if (hitBreakpoint) {
                result.put("stoppedReason", "breakpoint");
                result.put("breakpointAddress", currentPC.toString());
            } else if (reachedStopAddress) {
                result.put("stoppedReason", "targetAddress");
            } else {
                result.put("stoppedReason", "maxStepsReached");
            }
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error running emulator", e);
            session.setLastError("Error running emulator: " + e.getMessage());
            session.setRunning(false);
            result.put("success", false);
            result.put("error", e.getMessage());
            result.put("stepsExecuted", executedInstructions.size());
            result.put("executedInstructions", executedInstructions);
            return result;
        }
    }
    
    /**
     * Resets the emulator to its initial state.
     * 
     * @param session The emulator session
     * @return Map containing the result of the operation
     */
    public static Map<String, Object> resetEmulator(EmulatorSession session) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            Address startAddress = session.getStartAddress();
            
            if (startAddress == null) {
                result.put("success", false);
                result.put("error", "Emulator has not been initialized with a start address");
                return result;
            }
            
            // Reset registers to default values
            // Get architecture-specific register information
            ArchitectureHelper archHelper = new ArchitectureHelper(session.getProgram(), emulator);
            String pcRegName = archHelper.getProgramCounterRegisterName();
            String spRegName = archHelper.getStackPointerRegisterName();
            
            // Set default register values using writeRegister
            List<Register> registers = emulator.getProgram().getLanguage().getRegisters();
            for (Register reg : registers) {
                try {
                    String regName = reg.getName();
                    // Only set non-special registers to avoid conflicts
                    if (!regName.equals(pcRegName) && !regName.equals(spRegName)) {
                        // Use 0 as a default value for most registers
                        emulator.writeRegister(reg, BigInteger.ZERO);
                    }
                } catch (Exception e) {
                    // Some registers may not be writable; just skip them
                    Msg.debug(EmulatorOperations.class, "Could not reset register: " + reg.getName());
                }
            }
            
            // Set PC back to start address using architecture helper
            emulator.writeRegister(pcRegName, startAddress.getOffset());
            
            // Clear state tracking
            session.clearState();
            session.setStartAddress(startAddress);
            session.setRunning(true);
            session.setLastError(null);
            
            result.put("success", true);
            result.put("message", "Emulator reset to initial state");
            result.put("programCounter", startAddress.toString());
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error resetting emulator", e);
            result.put("success", false);
            result.put("error", "Error resetting emulator: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Import memory bytes from emulator to the Ghidra program.
     * 
     * @param session The emulator session
     * @param fromAddressStr Starting address to import (as a string)
     * @param lengthStr Length of bytes to import (as a string)
     * @return Map containing the result of the import operation
     */
    public static Map<String, Object> importMemory(EmulatorSession session, String fromAddressStr, String lengthStr) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            Program program = session.getProgram();
            EmulatorHelper emulator = session.getEmulator();
            
            // Parse addresses
            Address fromAddress = program.getAddressFactory().getAddress(fromAddressStr);
            if (fromAddress == null) {
                result.put("success", false);
                result.put("error", "Invalid from address: " + fromAddressStr);
                return result;
            }

            // Parse length (handle both decimal and hex formats)
            int length;
            try {
                if (lengthStr.startsWith("0x") || lengthStr.startsWith("0X")) {
                    length = Integer.parseInt(lengthStr.substring(2), 16);
                } else {
                    length = Integer.parseInt(lengthStr);
                }
            } catch (NumberFormatException e) {
                // Handle cases where the string is not a valid integer representation
                // or the value is outside the range of int (Integer.MIN_VALUE to Integer.MAX_VALUE)
                result.put("success", false);
                result.put("error", "Invalid length format or value out of range for an integer: " + lengthStr);
                return result;
            }

            // Validate the parsed length (must be positive)
            // The check for > Integer.MAX_VALUE is implicitly handled by the Integer.parseInt exception
            if (length <= 0) {
                result.put("success", false);
                result.put("error", "Invalid length: Length must be positive. Found: " + lengthStr);
                return result;
            }

            Address toAddress = fromAddress.add(length - 1);
            
            // Read the bytes from the emulator
            byte[] bytes = emulator.readMemory(fromAddress, length);
            if (bytes == null || bytes.length != length) {
                result.put("success", false);
                result.put("error", "Failed to read expected number of bytes from address: " + fromAddressStr);
                return result;
            }
            
            // Import bytes back to the program
            int bytesWritten = 0;
            try {
                for (int i = 0; i < bytes.length; i++) {
                    program.getMemory().setByte(fromAddress.add(i), bytes[i]);
                    bytesWritten++;
                }
            } catch (Exception e) {
                Msg.error(EmulatorOperations.class, "Error writing to program memory: " + e.getMessage(), e);
                result.put("partialSuccess", true);
                result.put("error", "Error writing to program memory: " + e.getMessage());
                result.put("bytesWritten", bytesWritten);
                return result;
            }
            
            result.put("success", true);
            result.put("bytesWritten", bytesWritten);
            result.put("fromAddress", fromAddress.toString());
            result.put("toAddress", toAddress.toString());
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorOperations.class, "Error importing memory", e);
            result.put("success", false);
            result.put("error", "Error importing memory: " + e.getMessage());
            return result;
        }
    }
}
