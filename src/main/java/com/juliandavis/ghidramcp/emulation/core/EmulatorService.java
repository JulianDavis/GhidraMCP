package com.juliandavis.ghidramcp.emulation.core;

import com.juliandavis.ghidramcp.core.service.Service;
import com.juliandavis.ghidramcp.emulation.arch.ArchitectureHelper;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;

/**
 * Core service that implements emulation functionality, managing sessions and 
 * providing methods for emulator control and state management.
 */
public class EmulatorService implements Service {
    
    public static final String SERVICE_NAME = "EmulatorService";
    
    private Program currentProgram;
    private final Map<String, EmulatorSession> sessions;
    
    /**
     * Creates a new EmulatorService.
     */
    public EmulatorService() {
        this.sessions = new HashMap<>();
    }
    
    @Override
    public String getName() {
        return SERVICE_NAME;
    }
    
    @Override
    public void initialize(Program program) {
        this.currentProgram = program;
        Msg.info(this, "EmulatorService initialized with program: " + 
                (program != null ? program.getName() : "null"));
    }
    
    @Override
    public void dispose() {
        // Dispose all active sessions
        sessions.values().forEach(EmulatorSession::dispose);
        sessions.clear();
        currentProgram = null;
        Msg.info(this, "EmulatorService disposed");
    }
    
    /**
     * Initializes a new emulation session with the specified starting address.
     * 
     * @param startAddress the address to start emulation from
     * @param writeTracking whether to enable memory write tracking
     * @return a map containing session information including the session ID
     */
    public Map<String, Object> initialize(String startAddress, boolean writeTracking) {
        if (currentProgram == null) {
            return createErrorResult("No program is loaded");
        }
        
        try {
            // Parse the start address
            Address addr = currentProgram.getAddressFactory().getAddress(startAddress);
            if (addr == null) {
                return createErrorResult("Invalid address: " + startAddress);
            }
            
            // Create a new emulator helper
            EmulatorHelper emulator = new EmulatorHelper(currentProgram);
            
            // Generate a unique session ID
            String sessionId = UUID.randomUUID().toString();
            
            // Create an architecture helper
            ArchitectureHelper archHelper = new ArchitectureHelper(currentProgram, emulator);
            
            // Set up the emulator
            String pcRegister = archHelper.getProgramCounterRegisterName();
            if (pcRegister == null) {
                emulator.dispose();
                return createErrorResult("Could not determine program counter register");
            }
            
            // Set the program counter to the start address
            emulator.writeRegister(pcRegister, addr.getOffset());
            
            // Create a new session
            EmulatorSession session = new EmulatorSession(sessionId, emulator, currentProgram);
            session.setStartAddress(addr);
            session.setCurrentAddress(addr);
            
            // Store the session
            sessions.put(sessionId, session);
            
            // Create the result
            Map<String, Object> result = new HashMap<>();
            result.put("sessionId", sessionId);
            result.put("programCounter", addr.toString());
            result.put("writeTracking", writeTracking);
            
            return result;
        } catch (Exception e) {
            return createErrorResult("Failed to initialize emulator: " + e.getMessage());
        }
    }
    
    /**
     * Gets the current state of the emulator for the specified session.
     * 
     * @param sessionId the session ID
     * @return a map containing the current emulator state
     */
    public Map<String, Object> getState(String sessionId) {
        EmulatorSession session = getSession(sessionId);
        if (session == null) {
            return createErrorResult("Invalid session ID: " + sessionId);
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            ArchitectureHelper archHelper = new ArchitectureHelper(currentProgram, emulator);
            
            // Get the program counter
            String pcRegister = archHelper.getProgramCounterRegisterName();
            if (pcRegister == null) {
                return createErrorResult("Could not determine program counter register");
            }
            
            BigInteger pcValue = emulator.readRegister(pcRegister);
            Address pcAddress = currentProgram.getAddressFactory().getAddress(pcValue.toString(16));
            
            // Create the result
            Map<String, Object> result = new HashMap<>();
            result.put("sessionId", sessionId);
            result.put("programCounter", pcAddress.toString());
            result.put("running", session.isRunning());
            
            if (session.getLastError() != null) {
                result.put("lastError", session.getLastError());
            }
            
            return result;
        } catch (Exception e) {
            return createErrorResult("Failed to get emulator state: " + e.getMessage());
        }
    }
    
    /**
     * Gets a session by ID.
     * 
     * @param sessionId the session ID
     * @return the session, or null if not found
     */
    public EmulatorSession getSession(String sessionId) {
        return sessions.get(sessionId);
    }
    
    /**
     * Gets all active sessions.
     * 
     * @return a map of session IDs to sessions
     */
    public Map<String, EmulatorSession> getSessions() {
        return Collections.unmodifiableMap(sessions);
    }
    
    /**
     * Steps the emulator forward by one instruction.
     * 
     * @param sessionId the session ID
     * @return a map containing the result of the step operation
     */
    public Map<String, Object> step(String sessionId) {
        EmulatorSession session = getSession(sessionId);
        if (session == null) {
            return createErrorResult("Invalid session ID: " + sessionId);
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            ArchitectureHelper archHelper = new ArchitectureHelper(currentProgram, emulator);
            
            // Get the program counter register
            String pcRegister = archHelper.getProgramCounterRegisterName();
            if (pcRegister == null) {
                return createErrorResult("Could not determine program counter register");
            }
            
            // Get the current address before stepping
            BigInteger pcValue = emulator.readRegister(pcRegister);
            Address pcAddressBefore = currentProgram.getAddressFactory().getAddress(pcValue.toString(16));
            
            // Execute one instruction
            boolean success = emulator.step(null);
            if (!success) {
                session.setLastError("Emulation step failed");
                return createErrorResult("Failed to execute instruction");
            }
            
            // Get the new program counter value
            pcValue = emulator.readRegister(pcRegister);
            Address pcAddressAfter = currentProgram.getAddressFactory().getAddress(pcValue.toString(16));
            
            // Update the session state
            session.setCurrentAddress(pcAddressAfter);
            
            // Create the result
            Map<String, Object> result = new HashMap<>();
            result.put("sessionId", sessionId);
            result.put("success", true);
            result.put("fromAddress", pcAddressBefore.toString());
            result.put("toAddress", pcAddressAfter.toString());
            
            return result;
        } catch (Exception e) {
            session.setLastError("Exception during step: " + e.getMessage());
            return createErrorResult("Failed to step emulator: " + e.getMessage());
        }
    }
    
    /**
     * Runs the emulator until a condition is met.
     * 
     * @param sessionId the session ID
     * @param maxSteps maximum number of steps to execute
     * @param stopOnBreakpoint whether to stop at breakpoints
     * @param stopAddress optional address to stop at
     * @return a map containing the result of the run operation
     */
    public Map<String, Object> run(String sessionId, int maxSteps, boolean stopOnBreakpoint, String stopAddress) {
        EmulatorSession session = getSession(sessionId);
        if (session == null) {
            return createErrorResult("Invalid session ID: " + sessionId);
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            ArchitectureHelper archHelper = new ArchitectureHelper(currentProgram, emulator);
            
            // Get the program counter register
            String pcRegister = archHelper.getProgramCounterRegisterName();
            if (pcRegister == null) {
                return createErrorResult("Could not determine program counter register");
            }
            
            // Get the current address before running
            BigInteger pcValue = emulator.readRegister(pcRegister);
            Address pcAddressBefore = currentProgram.getAddressFactory().getAddress(pcValue.toString(16));
            
            // Parse the stop address if provided
            Address stopAddr = null;
            if (stopAddress != null && !stopAddress.isEmpty()) {
                stopAddr = currentProgram.getAddressFactory().getAddress(stopAddress);
                if (stopAddr == null) {
                    return createErrorResult("Invalid stop address: " + stopAddress);
                }
            }
            
            // Set the session as running
            session.setRunning(true);
            
            // Run the emulator
            int stepsExecuted = 0;
            boolean hitBreakpoint = false;
            boolean reachedStopAddress = false;
            
            try {
                for (stepsExecuted = 0; stepsExecuted < maxSteps; stepsExecuted++) {
                    // Check if we've reached the stop address
                    pcValue = emulator.readRegister(pcRegister);
                    Address currentAddr = currentProgram.getAddressFactory().getAddress(pcValue.toString(16));
                    
                    if (stopAddr != null && currentAddr.equals(stopAddr)) {
                        reachedStopAddress = true;
                        break;
                    }
                    
                    // Check if we've hit a breakpoint
                    if (stopOnBreakpoint && session.getBreakpoints().contains(currentAddr)) {
                        hitBreakpoint = true;
                        break;
                    }
                    
                    // Execute one instruction
                    boolean success = emulator.step(null);
                    if (!success) {
                        session.setLastError("Emulation step failed during run");
                        break;
                    }
                }
            } finally {
                // Set the session as not running
                session.setRunning(false);
            }
            
            // Get the final program counter value
            pcValue = emulator.readRegister(pcRegister);
            Address pcAddressAfter = currentProgram.getAddressFactory().getAddress(pcValue.toString(16));
            
            // Update the session state
            session.setCurrentAddress(pcAddressAfter);
            
            // Create the result
            Map<String, Object> result = new HashMap<>();
            result.put("sessionId", sessionId);
            result.put("stepsExecuted", stepsExecuted);
            result.put("fromAddress", pcAddressBefore.toString());
            result.put("toAddress", pcAddressAfter.toString());
            result.put("hitBreakpoint", hitBreakpoint);
            result.put("reachedStopAddress", reachedStopAddress);
            result.put("hitMaxSteps", stepsExecuted >= maxSteps);
            
            return result;
        } catch (Exception e) {
            session.setRunning(false);
            session.setLastError("Exception during run: " + e.getMessage());
            return createErrorResult("Failed to run emulator: " + e.getMessage());
        }
    }
    
    /**
     * Resets the emulator to its initial state.
     * 
     * @param sessionId the session ID
     * @return a map containing the result of the reset operation
     */
    public Map<String, Object> reset(String sessionId) {
        EmulatorSession session = getSession(sessionId);
        if (session == null) {
            return createErrorResult("Invalid session ID: " + sessionId);
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            ArchitectureHelper archHelper = new ArchitectureHelper(currentProgram, emulator);
            
            // Get the program counter register
            String pcRegister = archHelper.getProgramCounterRegisterName();
            if (pcRegister == null) {
                return createErrorResult("Could not determine program counter register");
            }
            
            // Reset the emulator state
            emulator.clearAllBreakpoints();
            
            // Reset the program counter to the start address
            Address startAddress = session.getStartAddress();
            emulator.writeRegister(pcRegister, startAddress.getOffset());
            
            // Reset session state
            session.setCurrentAddress(startAddress);
            session.setRunning(false);
            session.setLastError(null);
            session.clearState();
            
            // Create the result
            Map<String, Object> result = new HashMap<>();
            result.put("sessionId", sessionId);
            result.put("programCounter", startAddress.toString());
            result.put("message", "Emulator reset to initial state");
            
            return result;
        } catch (Exception e) {
            session.setLastError("Exception during reset: " + e.getMessage());
            return createErrorResult("Failed to reset emulator: " + e.getMessage());
        }
    }
    
    /**
     * Sets a breakpoint at the specified address.
     * 
     * @param sessionId the session ID
     * @param address the address to set the breakpoint at
     * @return a map containing the result of the operation
     */
    public Map<String, Object> setBreakpoint(String sessionId, String address) {
        EmulatorSession session = getSession(sessionId);
        if (session == null) {
            return createErrorResult("Invalid session ID: " + sessionId);
        }
        
        try {
            // Parse the address
            Address addr = currentProgram.getAddressFactory().getAddress(address);
            if (addr == null) {
                return createErrorResult("Invalid address: " + address);
            }
            
            // Add the breakpoint to the session
            boolean added = session.addBreakpoint(addr);
            
            // Add the breakpoint to the emulator
            session.getEmulator().setBreakpoint(addr);
            
            // Create the result
            Map<String, Object> result = new HashMap<>();
            result.put("address", address);
            result.put("added", added);
            
            return result;
        } catch (Exception e) {
            return createErrorResult("Failed to set breakpoint: " + e.getMessage());
        }
    }
    
    /**
     * Clears a breakpoint at the specified address.
     * 
     * @param sessionId the session ID
     * @param address the address to clear the breakpoint from
     * @return a map containing the result of the operation
     */
    public Map<String, Object> clearBreakpoint(String sessionId, String address) {
        EmulatorSession session = getSession(sessionId);
        if (session == null) {
            return createErrorResult("Invalid session ID: " + sessionId);
        }
        
        try {
            // Parse the address
            Address addr = currentProgram.getAddressFactory().getAddress(address);
            if (addr == null) {
                return createErrorResult("Invalid address: " + address);
            }
            
            // Remove the breakpoint from the session
            boolean removed = session.removeBreakpoint(addr);
            
            // Remove the breakpoint from the emulator
            session.getEmulator().clearBreakpoint(addr);
            
            // Create the result
            Map<String, Object> result = new HashMap<>();
            result.put("address", address);
            result.put("removed", removed);
            
            return result;
        } catch (Exception e) {
            return createErrorResult("Failed to clear breakpoint: " + e.getMessage());
        }
    }
    
    /**
     * Gets all active breakpoints for the session.
     * 
     * @param sessionId the session ID
     * @return a map containing the breakpoints
     */
    public Map<String, Object> getBreakpoints(String sessionId) {
        EmulatorSession session = getSession(sessionId);
        if (session == null) {
            return createErrorResult("Invalid session ID: " + sessionId);
        }
        
        try {
            // Get the breakpoints
            Map<String, Object> result = new HashMap<>();
            result.put("breakpoints", session.getBreakpoints().stream()
                    .map(Address::toString)
                    .toArray(String[]::new));
            result.put("count", session.getBreakpoints().size());
            
            return result;
        } catch (Exception e) {
            return createErrorResult("Failed to get breakpoints: " + e.getMessage());
        }
    }
    
    /**
     * Sets a conditional breakpoint at the specified address.
     * 
     * @param sessionId the session ID
     * @param address the address to set the breakpoint at
     * @param condition the condition expression
     * @return a map containing the result of the operation
     */
    public Map<String, Object> setConditionalBreakpoint(String sessionId, String address, String condition) {
        EmulatorSession session = getSession(sessionId);
        if (session == null) {
            return createErrorResult("Invalid session ID: " + sessionId);
        }
        
        try {
            // Parse the address
            Address addr = currentProgram.getAddressFactory().getAddress(address);
            if (addr == null) {
                return createErrorResult("Invalid address: " + address);
            }
            
            // Add the conditional breakpoint to the session
            session.addConditionalBreakpoint(addr, condition);
            
            // Add the breakpoint to the emulator
            session.getEmulator().setBreakpoint(addr);
            
            // Create the result
            Map<String, Object> result = new HashMap<>();
            result.put("address", address);
            result.put("condition", condition);
            result.put("message", "Conditional breakpoint set");
            
            return result;
        } catch (Exception e) {
            return createErrorResult("Failed to set conditional breakpoint: " + e.getMessage());
        }
    }
    
    /**
     * Gets all conditional breakpoints for the session.
     * 
     * @param sessionId the session ID
     * @return a map containing the conditional breakpoints
     */
    public Map<String, Object> getConditionalBreakpoints(String sessionId) {
        EmulatorSession session = getSession(sessionId);
        if (session == null) {
            return createErrorResult("Invalid session ID: " + sessionId);
        }
        
        try {
            // Get the conditional breakpoints
            Map<String, Object> result = new HashMap<>();
            result.put("breakpoints", session.getConditionalBreakpoints());
            result.put("count", session.getConditionalBreakpoints().size());
            
            return result;
        } catch (Exception e) {
            return createErrorResult("Failed to get conditional breakpoints: " + e.getMessage());
        }
    }
    
    /**
     * Sets the value of a register.
     * 
     * @param sessionId the session ID
     * @param register the register name
     * @param value the value to set
     * @return a map containing the result of the operation
     */
    public Map<String, Object> setRegisterValue(String sessionId, String register, String value) {
        EmulatorSession session = getSession(sessionId);
        if (session == null) {
            return createErrorResult("Invalid session ID: " + sessionId);
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            
            // Parse the value
            BigInteger registerValue;
            if (value.toLowerCase().startsWith("0x")) {
                registerValue = new BigInteger(value.substring(2), 16);
            } else {
                registerValue = new BigInteger(value);
            }
            
            // Set the register value
            emulator.writeRegister(register, registerValue);
            
            // Track the register write
            session.trackRegisterWrite(register, registerValue.longValue());
            
            // Create the result
            Map<String, Object> result = new HashMap<>();
            result.put("register", register);
            result.put("value", "0x" + registerValue.toString(16));
            result.put("decimal", registerValue.toString());
            
            return result;
        } catch (Exception e) {
            return createErrorResult("Failed to set register value: " + e.getMessage());
        }
    }
    
    /**
     * Gets the value of a register.
     * 
     * @param sessionId the session ID
     * @param register the register name
     * @return a map containing the register value
     */
    public Map<String, Object> getRegisterValue(String sessionId, String register) {
        EmulatorSession session = getSession(sessionId);
        if (session == null) {
            return createErrorResult("Invalid session ID: " + sessionId);
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            
            // Read the register value
            BigInteger registerValue = emulator.readRegister(register);
            
            // Create the result
            Map<String, Object> result = new HashMap<>();
            result.put("register", register);
            result.put("value", "0x" + registerValue.toString(16));
            result.put("decimal", registerValue.toString());
            
            return result;
        } catch (Exception e) {
            return createErrorResult("Failed to get register value: " + e.getMessage());
        }
    }
    
    /**
     * Gets all registers and their values.
     * 
     * @param sessionId the session ID
     * @return a map containing all registers and their values
     */
    public Map<String, Object> getRegisters(String sessionId) {
        EmulatorSession session = getSession(sessionId);
        if (session == null) {
            return createErrorResult("Invalid session ID: " + sessionId);
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            ArchitectureHelper archHelper = new ArchitectureHelper(currentProgram, emulator);
            
            // Get the program counter and stack pointer register names
            String pcRegister = archHelper.getProgramCounterRegisterName();
            String spRegister = archHelper.getStackPointerRegisterName();
            
            // Get all registers
            List<Map<String, Object>> registers = new ArrayList<>();
            
            // For each available register, read its value and add to the list
            for (ghidra.program.model.lang.Register register : currentProgram.getLanguage().getRegisters()) {
                try {
                    String name = register.getName();
                    
                    // Skip registers we can't read
                    if (!emulator.hasRegister(name)) {
                        continue;
                    }
                    
                    BigInteger value = emulator.readRegister(name);
                    
                    Map<String, Object> reg = new HashMap<>();
                    reg.put("name", name);
                    reg.put("value", "0x" + value.toString(16));
                    reg.put("decimal", value.toString());
                    
                    // Mark special registers
                    if (name.equals(pcRegister)) {
                        reg.put("isProgramCounter", true);
                    }
                    if (name.equals(spRegister)) {
                        reg.put("isStackPointer", true);
                    }
                    
                    registers.add(reg);
                } catch (Exception e) {
                    // Skip registers that we can't read
                    Msg.debug(this, "Could not read register " + register.getName() + ": " + e.getMessage());
                }
            }
            
            // Create the result
            Map<String, Object> result = new HashMap<>();
            result.put("registers", registers);
            result.put("count", registers.size());
            
            return result;
        } catch (Exception e) {
            return createErrorResult("Failed to get registers: " + e.getMessage());
        }
    }
    
    /**
     * Reads bytes from the specified memory address.
     * 
     * @param sessionId the session ID
     * @param address the address to read from
     * @param length the number of bytes to read
     * @return a map containing the memory data
     */
    public Map<String, Object> readMemory(String sessionId, String address, int length) {
        EmulatorSession session = getSession(sessionId);
        if (session == null) {
            return createErrorResult("Invalid session ID: " + sessionId);
        }
        
        // Limit the number of bytes to read
        int maxLength = 4096;
        if (length > maxLength) {
            return createErrorResult("Requested length exceeds maximum (" + maxLength + " bytes)");
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            
            // Parse the address
            Address addr = currentProgram.getAddressFactory().getAddress(address);
            if (addr == null) {
                return createErrorResult("Invalid address: " + address);
            }
            
            // Read the memory
            byte[] bytes = new byte[length];
            boolean success = emulator.readMemory(addr, bytes);
            if (!success) {
                return createErrorResult("Failed to read memory from address: " + address);
            }
            
            // Track the memory read
            session.trackMemoryRead(addr, bytes);
            
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
            
            // Create the result
            Map<String, Object> result = new HashMap<>();
            result.put("address", address);
            result.put("length", length);
            result.put("hexValue", hex.toString());
            result.put("asciiValue", ascii.toString());
            
            return result;
        } catch (Exception e) {
            return createErrorResult("Failed to read memory: " + e.getMessage());
        }
    }
    
    /**
     * Writes bytes to the specified memory address.
     * 
     * @param sessionId the session ID
     * @param address the address to write to
     * @param bytesHex the bytes to write as a hex string
     * @return a map containing the result of the operation
     */
    public Map<String, Object> writeMemory(String sessionId, String address, String bytesHex) {
        EmulatorSession session = getSession(sessionId);
        if (session == null) {
            return createErrorResult("Invalid session ID: " + sessionId);
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            
            // Parse the address
            Address addr = currentProgram.getAddressFactory().getAddress(address);
            if (addr == null) {
                return createErrorResult("Invalid address: " + address);
            }
            
            // Parse the hex string
            if (bytesHex.length() % 2 != 0) {
                return createErrorResult("Invalid hex string length (must be even)");
            }
            
            byte[] bytes = new byte[bytesHex.length() / 2];
            for (int i = 0; i < bytes.length; i++) {
                String byteStr = bytesHex.substring(i * 2, i * 2 + 2);
                bytes[i] = (byte) Integer.parseInt(byteStr, 16);
            }
            
            // Write the memory
            boolean success = emulator.writeMemory(addr, bytes);
            if (!success) {
                return createErrorResult("Failed to write memory to address: " + address);
            }
            
            // Track the memory write
            session.trackMemoryWrite(addr, bytes);
            
            // Create the result
            Map<String, Object> result = new HashMap<>();
            result.put("address", address);
            result.put("bytesWritten", bytes.length);
            
            return result;
        } catch (Exception e) {
            return createErrorResult("Failed to write memory: " + e.getMessage());
        }
    }
    
    /**
     * Gets a list of memory locations that were written during emulation.
     * 
     * @param sessionId the session ID
     * @return a map containing memory write information
     */
    public Map<String, Object> getWrites(String sessionId) {
        EmulatorSession session = getSession(sessionId);
        if (session == null) {
            return createErrorResult("Invalid session ID: " + sessionId);
        }
        
        try {
            // Get the memory writes
            Map<Address, Byte> memoryWrites = session.getMemoryWrites();
            
            // Group contiguous writes
            List<Map<String, Object>> writes = new ArrayList<>();
            if (!memoryWrites.isEmpty()) {
                Address currentAddr = null;
                List<Byte> currentBytes = new ArrayList<>();
                
                for (Map.Entry<Address, Byte> entry : new TreeMap<>(memoryWrites).entrySet()) {
                    Address addr = entry.getKey();
                    Byte value = entry.getValue();
                    
                    if (currentAddr == null) {
                        // First entry
                        currentAddr = addr;
                        currentBytes.add(value);
                    } else if (addr.equals(currentAddr.add(currentBytes.size()))) {
                        // Contiguous address, add to current group
                        currentBytes.add(value);
                    } else {
                        // Non-contiguous, create a new group
                        addWriteGroup(writes, currentAddr, currentBytes);
                        currentAddr = addr;
                        currentBytes.clear();
                        currentBytes.add(value);
                    }
                }
                
                // Add the final group
                if (currentAddr != null) {
                    addWriteGroup(writes, currentAddr, currentBytes);
                }
            }
            
            // Create the result
            Map<String, Object> result = new HashMap<>();
            result.put("writes", writes);
            result.put("count", writes.size());
            result.put("totalBytes", memoryWrites.size());
            
            return result;
        } catch (Exception e) {
            return createErrorResult("Failed to get memory writes: " + e.getMessage());
        }
    }
    
    /**
     * Gets a list of memory locations that were read during emulation.
     * 
     * @param sessionId the session ID
     * @return a map containing memory read information
     */
    public Map<String, Object> getReads(String sessionId) {
        EmulatorSession session = getSession(sessionId);
        if (session == null) {
            return createErrorResult("Invalid session ID: " + sessionId);
        }
        
        try {
            // Get the memory reads
            Map<Address, Byte> memoryReads = session.getMemoryReads();
            
            // Group contiguous reads
            List<Map<String, Object>> reads = new ArrayList<>();
            if (!memoryReads.isEmpty()) {
                Address currentAddr = null;
                List<Byte> currentBytes = new ArrayList<>();
                
                for (Map.Entry<Address, Byte> entry : new TreeMap<>(memoryReads).entrySet()) {
                    Address addr = entry.getKey();
                    Byte value = entry.getValue();
                    
                    if (currentAddr == null) {
                        // First entry
                        currentAddr = addr;
                        currentBytes.add(value);
                    } else if (addr.equals(currentAddr.add(currentBytes.size()))) {
                        // Contiguous address, add to current group
                        currentBytes.add(value);
                    } else {
                        // Non-contiguous, create a new group
                        addReadGroup(reads, currentAddr, currentBytes);
                        currentAddr = addr;
                        currentBytes.clear();
                        currentBytes.add(value);
                    }
                }
                
                // Add the final group
                if (currentAddr != null) {
                    addReadGroup(reads, currentAddr, currentBytes);
                }
            }
            
            // Create the result
            Map<String, Object> result = new HashMap<>();
            result.put("reads", reads);
            result.put("count", reads.size());
            result.put("totalBytes", memoryReads.size());
            
            return result;
        } catch (Exception e) {
            return createErrorResult("Failed to get memory reads: " + e.getMessage());
        }
    }
    
    /**
     * Sets memory read tracking in the emulator.
     * 
     * @param sessionId the session ID
     * @param enable whether to enable or disable tracking
     * @return a map containing the result of the operation
     */
    public Map<String, Object> setMemoryReadTracking(String sessionId, boolean enable) {
        EmulatorSession session = getSession(sessionId);
        if (session == null) {
            return createErrorResult("Invalid session ID: " + sessionId);
        }
        
        try {
            // Set the tracking state
            session.setTrackMemoryReads(enable);
            
            // Create the result
            Map<String, Object> result = new HashMap<>();
            result.put("tracking", enable);
            result.put("message", "Memory read tracking " + (enable ? "enabled" : "disabled"));
            
            return result;
        } catch (Exception e) {
            return createErrorResult("Failed to set memory read tracking: " + e.getMessage());
        }
    }
    
    /**
     * Sets stack change tracking in the emulator.
     * 
     * @param sessionId the session ID
     * @param enable whether to enable or disable tracking
     * @return a map containing the result of the operation
     */
    public Map<String, Object> setStackChangeTracking(String sessionId, boolean enable) {
        EmulatorSession session = getSession(sessionId);
        if (session == null) {
            return createErrorResult("Invalid session ID: " + sessionId);
        }
        
        try {
            // Set the tracking state
            session.setTrackStackChanges(enable);
            
            // Create the result
            Map<String, Object> result = new HashMap<>();
            result.put("tracking", enable);
            result.put("message", "Stack change tracking " + (enable ? "enabled" : "disabled"));
            
            return result;
        } catch (Exception e) {
            return createErrorResult("Failed to set stack change tracking: " + e.getMessage());
        }
    }
    
    /**
     * Gets the stack trace from the emulator.
     * 
     * @param sessionId the session ID
     * @return a map containing stack trace information
     */
    public Map<String, Object> getStackTrace(String sessionId) {
        EmulatorSession session = getSession(sessionId);
        if (session == null) {
            return createErrorResult("Invalid session ID: " + sessionId);
        }
        
        try {
            // Get the stack trace
            List<Map<String, Object>> stackTrace = session.getStackTrace();
            
            // Create the result
            Map<String, Object> result = new HashMap<>();
            result.put("stackTrace", stackTrace);
            result.put("count", stackTrace.size());
            
            return result;
        } catch (Exception e) {
            return createErrorResult("Failed to get stack trace: " + e.getMessage());
        }
    }
    
    /**
     * Imports memory bytes from emulator to the Ghidra program.
     * 
     * @param sessionId the session ID
     * @param fromAddress starting address to import
     * @param length length of bytes to import
     * @return a map containing the result of the import operation
     */
    public Map<String, Object> importMemory(String sessionId, String fromAddress, String length) {
        EmulatorSession session = getSession(sessionId);
        if (session == null) {
            return createErrorResult("Invalid session ID: " + sessionId);
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            
            // Parse the address
            Address addr = currentProgram.getAddressFactory().getAddress(fromAddress);
            if (addr == null) {
                return createErrorResult("Invalid address: " + fromAddress);
            }
            
            // Parse the length
            int len;
            try {
                if (length.toLowerCase().startsWith("0x")) {
                    len = Integer.parseInt(length.substring(2), 16);
                } else {
                    len = Integer.parseInt(length);
                }
            } catch (NumberFormatException e) {
                return createErrorResult("Invalid length: " + length);
            }
            
            // Limit the size of the import
            int maxLength = 16384; // 16KB
            if (len > maxLength) {
                return createErrorResult("Requested length exceeds maximum (" + maxLength + " bytes)");
            }
            
            // Read the memory from the emulator
            byte[] bytes = new byte[len];
            boolean success = emulator.readMemory(addr, bytes);
            if (!success) {
                return createErrorResult("Failed to read memory from emulator");
            }
            
            // Write the memory to the program
            try {
                int bytesWritten = currentProgram.getMemory().setBytes(addr, bytes);
                
                // Create the result
                Map<String, Object> result = new HashMap<>();
                result.put("bytesWritten", bytesWritten);
                result.put("fromAddress", fromAddress);
                result.put("toAddress", addr.add(bytesWritten - 1).toString());
                
                return result;
            } catch (Exception e) {
                return createErrorResult("Failed to write memory to program: " + e.getMessage());
            }
        } catch (Exception e) {
            return createErrorResult("Failed to import memory: " + e.getMessage());
        }
    }
    
    /**
     * Adds a group of contiguous memory writes to the result list.
     * 
     * @param writes the list to add to
     * @param startAddr the starting address of the group
     * @param bytes the bytes in the group
     */
    private void addWriteGroup(List<Map<String, Object>> writes, Address startAddr, List<Byte> bytes) {
        byte[] byteArray = new byte[bytes.size()];
        for (int i = 0; i < bytes.size(); i++) {
            byteArray[i] = bytes.get(i);
        }
        
        // Convert to hex string
        StringBuilder hex = new StringBuilder();
        for (byte b : byteArray) {
            hex.append(String.format("%02x", b));
        }
        
        // Convert to ASCII string
        StringBuilder ascii = new StringBuilder();
        for (byte b : byteArray) {
            ascii.append(isPrintable(b) ? (char) b : '.');
        }
        
        Map<String, Object> write = new HashMap<>();
        write.put("address", startAddr.toString());
        write.put("length", byteArray.length);
        write.put("hexValue", hex.toString());
        write.put("asciiValue", ascii.toString());
        
        writes.add(write);
    }
    
    /**
     * Adds a group of contiguous memory reads to the result list.
     * 
     * @param reads the list to add to
     * @param startAddr the starting address of the group
     * @param bytes the bytes in the group
     */
    private void addReadGroup(List<Map<String, Object>> reads, Address startAddr, List<Byte> bytes) {
        byte[] byteArray = new byte[bytes.size()];
        for (int i = 0; i < bytes.size(); i++) {
            byteArray[i] = bytes.get(i);
        }
        
        // Convert to hex string
        StringBuilder hex = new StringBuilder();
        for (byte b : byteArray) {
            hex.append(String.format("%02x", b));
        }
        
        // Convert to ASCII string
        StringBuilder ascii = new StringBuilder();
        for (byte b : byteArray) {
            ascii.append(isPrintable(b) ? (char) b : '.');
        }
        
        Map<String, Object> read = new HashMap<>();
        read.put("address", startAddr.toString());
        read.put("length", byteArray.length);
        read.put("hexValue", hex.toString());
        read.put("asciiValue", ascii.toString());
        
        reads.add(read);
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
     * Creates an error result map.
     * 
     * @param errorMessage the error message
     * @return a map containing the error information
     */
    private Map<String, Object> createErrorResult(String errorMessage) {
        Map<String, Object> result = new HashMap<>();
        result.put("error", errorMessage);
        return result;
    }
}
