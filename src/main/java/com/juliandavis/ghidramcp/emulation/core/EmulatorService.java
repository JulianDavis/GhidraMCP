package com.juliandavis.ghidramcp.emulation.core;

import com.juliandavis.ghidramcp.core.service.Service;
import com.juliandavis.ghidramcp.emulation.arch.ArchitectureHelper;
import com.juliandavis.ghidramcp.emulation.io.StdioEmulationHelper;
import com.juliandavis.ghidramcp.emulation.syscall.SyscallMappings;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.emulator.MemoryAccessFilter;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
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
     * Creates a standardized error result map.
     *
     * @param errorMessage the error message
     * @param errorCode optional error code (default: 400)
     * @return a map containing the standardized error information
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
     * Creates a standardized error result map with default error code (400).
     *
     * @param errorMessage the error message
     * @return a map containing the standardized error information
     */
    private Map<String, Object> createErrorResult(String errorMessage) {
        return createErrorResult(errorMessage, 400);
    }
    
    /**
     * Creates a standardized success result map.
     *
     * @param data the data to include in the response
     * @return a map containing the standardized success information
     */
    private Map<String, Object> createSuccessResult(Map<String, Object> data) {
        Map<String, Object> response = new HashMap<>();
        
        // Standard top-level structure
        response.put("status", "success");
        response.put("data", data);
        
        return response;
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

            // Create a new session
            EmulatorSession session = new EmulatorSession(sessionId, emulator, currentProgram);

            // Initialize the emulator
            if (!initializeEmulator(session, addr, writeTracking)) {
                emulator.dispose();
                return createErrorResult("Failed to initialize emulator: " + session.getLastError());
            }

            // Store the session
            sessions.put(sessionId, session);

            // Create data for the success response
            Map<String, Object> data = new HashMap<>();
            data.put("sessionId", sessionId);
            data.put("programCounter", addr.toString());
            data.put("writeTracking", writeTracking);

            // Return a standardized success response
            return createSuccessResult(data);
        } catch (Exception e) {
            return createErrorResult("Failed to initialize emulator: " + e.getMessage());
        }
    }

    /**
     * Initializes an emulator session with the specified address and configuration.
     *
     * @param session The emulator session to initialize
     * @param startAddress The address to start emulation from
     * @param writeTracking Whether to enable write tracking
     * @return true if initialization successful, false otherwise
     */
    private boolean initializeEmulator(EmulatorSession session, Address startAddress, boolean writeTracking) {
        if (session == null) {
            return false;
        }

        try {
            session.setStartAddress(startAddress);

            // Configure the emulator
            EmulatorHelper emulator = session.getEmulator();

            // Register memory access filter for tracking
            emulator.getEmulator().addMemoryAccessFilter(new MemoryAccessFilter() {
                @Override
                protected void processRead(AddressSpace space, long offset, int size, byte[] values) {
                    // Track memory reads when enabled
                    if (session.isTrackingMemoryReads() && values != null) {
                        // Convert AddressSpace and offset to an Address object
                        Address address = space.getAddress(offset);
                        session.trackMemoryRead(address, values);
                    }
                }

                @Override
                protected void processWrite(AddressSpace space, long offset, int size, byte[] values) {
                    // Track memory writes when enabled
                    if (writeTracking && values != null) {
                        // Convert AddressSpace and offset to an Address object
                        Address address = space.getAddress(offset);
                        session.trackMemoryWrite(address, values);
                    }
                }
            });

            // Register the stdio emulation helper
            StdioEmulationHelper stdioHelper = new StdioEmulationHelper(session);
            stdioHelper.register();

            // Log information about syscall support for this binary
            Program program = session.getProgram();
            ArchitectureHelper archHelper = new ArchitectureHelper(program, emulator);
            String os = SyscallMappings.determineOS(program);
            String processor = archHelper.getProcessorName();

            if (SyscallMappings.isOSSupported(os) && SyscallMappings.isSupported(os, processor)) {
                // Get all supported syscalls to log for debugging
                Map<Integer, SyscallMappings.SyscallInfo> allSyscalls = SyscallMappings.getAllSyscalls(os, processor);
                Msg.info(this, "Loaded " + allSyscalls.size() + " syscall mappings for "
                        + os + "/" + processor);
            } else {
                Msg.warn(this, "Limited or no syscall support for " + os + "/" + processor);
            }

            // Initialize registers to reasonable defaults
            String pcRegName = archHelper.getProgramCounterRegisterName();
            String spRegName = archHelper.getStackPointerRegisterName();

            if (pcRegName == null) {
                session.setLastError("Could not determine program counter register");
                return false;
            }

            // Initialize all registers to zero except PC and SP
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
                    Msg.debug(this, "Could not initialize register: " + reg.getName());
                }
            }

            // Set the program counter to the start address
            emulator.writeRegister(pcRegName, startAddress.getOffset());

            session.clearState();
            session.setRunning(true);
            session.setLastError(null);

            return true;
        } catch (Exception e) {
            Msg.error(this, "Error initializing emulator", e);
            session.setLastError("Error initializing emulator: " + e.getMessage());
            session.setRunning(false);
            return false;
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

            // Create data for the success response
            Map<String, Object> data = new HashMap<>();
            data.put("sessionId", sessionId);
            data.put("programCounter", pcAddress.toString());
            data.put("running", session.isRunning());

            if (session.getLastError() != null) {
                data.put("lastError", session.getLastError());
            }

            // Return a standardized success response
            return createSuccessResult(data);
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

            // Track stack changes if enabled
            if (session.isTrackingStackChanges()) {
                trackStackChanges(session, pcAddressBefore);
            }

            // Create data for the success response
            Map<String, Object> data = new HashMap<>();
            data.put("sessionId", sessionId);
            data.put("fromAddress", pcAddressBefore.toString());
            data.put("toAddress", pcAddressAfter.toString());

            // Return a standardized success response
            return createSuccessResult(data);
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
            int stepsExecuted;
            boolean hitBreakpoint = false;
            boolean reachedStopAddress = false;

            try {
                // Start with the initial PC value
                pcValue = emulator.readRegister(pcRegister);
                Address currentAddr = currentProgram.getAddressFactory().getAddress(pcValue.toString(16));
                
                for (stepsExecuted = 0; stepsExecuted < maxSteps; stepsExecuted++) {
                    // Check if we've reached the stop address
                    if (currentAddr.equals(stopAddr)) {
                        reachedStopAddress = true;
                        break;
                    }

                    // Check if we've hit a breakpoint
                    if (stopOnBreakpoint && session.getBreakpoints().contains(currentAddr)) {
                        // Get condition if this is a conditional breakpoint
                        String condition = session.getConditionalBreakpoints().get(currentAddr.toString());

                        // Break if: this is a regular breakpoint OR condition evaluates to true
                        if (condition == null || evaluateBreakpointCondition(session, condition)) {
                            hitBreakpoint = true;
                            break;
                        }
                        // Otherwise continue execution (conditional breakpoint with false condition)
                    }

                    // Save current address before stepping (for stack tracking)
                    Address addressBeforeStep = currentAddr;

                    // Execute one instruction
                    boolean success = emulator.step(null);
                    if (!success) {
                        session.setLastError("Emulation step failed during run");
                        break;
                    }
                    
                    // Track stack changes if enabled - using the address from BEFORE the step
                    if (session.isTrackingStackChanges()) {
                        trackStackChanges(session, addressBeforeStep);
                    }
                    
                    // Update current address for next iteration (PC has changed)
                    pcValue = emulator.readRegister(pcRegister);
                    currentAddr = currentProgram.getAddressFactory().getAddress(pcValue.toString(16));
                }
            } finally {
                // Set the session as not running
                session.setRunning(false);
            }

            // Get the final program counter value
            pcValue = emulator.readRegister(pcRegister);
            Address pcAddressAfter = currentProgram.getAddressFactory().getAddress(pcValue.toString(16));

            // Track stack changes if enabled
            if (session.isTrackingStackChanges()) {
                trackStackChanges(session, pcAddressBefore);
            }

            // Create data for the success response
            Map<String, Object> data = new HashMap<>();
            data.put("sessionId", sessionId);
            data.put("stepsExecuted", stepsExecuted);
            data.put("fromAddress", pcAddressBefore.toString());
            data.put("toAddress", pcAddressAfter.toString());
            data.put("hitBreakpoint", hitBreakpoint);
            data.put("reachedStopAddress", reachedStopAddress);
            data.put("hitMaxSteps", stepsExecuted >= maxSteps);

            // Return a standardized success response
            return createSuccessResult(data);
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
            // Clear all breakpoints by iterating through them
            for (Address bpAddr : session.getBreakpoints()) {
                emulator.clearBreakpoint(bpAddr);
            }
            session.clearBreakpoints();

            // Reset the program counter to the start address
            Address startAddress = session.getStartAddress();
            emulator.writeRegister(pcRegister, startAddress.getOffset());

            // Reset session state
            session.setRunning(false);
            session.setLastError(null);
            session.clearState();

            // Create data for the success response
            Map<String, Object> data = new HashMap<>();
            data.put("sessionId", sessionId);
            data.put("programCounter", startAddress.toString());
            data.put("message", "Emulator reset to initial state");

            // Return a standardized success response
            return createSuccessResult(data);
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

            // Create data for the success response
            Map<String, Object> data = new HashMap<>();
            data.put("address", address);
            data.put("added", added);

            // Return a standardized success response
            return createSuccessResult(data);
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

            // Create data for the success response
            Map<String, Object> data = new HashMap<>();
            data.put("address", address);
            data.put("removed", removed);

            // Return a standardized success response
            return createSuccessResult(data);
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
            // Create data for the success response
            Map<String, Object> data = new HashMap<>();
            data.put("breakpoints", session.getBreakpoints().stream()
                    .map(Address::toString)
                    .toArray(String[]::new));
            data.put("count", session.getBreakpoints().size());

            // Return a standardized success response
            return createSuccessResult(data);
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

            // Create data for the success response
            Map<String, Object> data = new HashMap<>();
            data.put("address", address);
            data.put("condition", condition);
            data.put("message", "Conditional breakpoint set");

            // Return a standardized success response
            return createSuccessResult(data);
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
            // Create data for the success response
            Map<String, Object> data = new HashMap<>();
            data.put("breakpoints", session.getConditionalBreakpoints());
            data.put("count", session.getConditionalBreakpoints().size());

            // Return a standardized success response
            return createSuccessResult(data);
        } catch (Exception e) {
            return createErrorResult("Failed to get conditional breakpoints: " + e.getMessage());
        }
    }

    /**
     * Provides stdin data to the emulator.
     *
     * @param sessionId the session ID
     * @param data the data to provide
     * @return a map containing the result of the operation
     */
    public Map<String, Object> provideStdinData(String sessionId, String data) {
        EmulatorSession session = getSession(sessionId);
        if (session == null) {
            return createErrorResult("Invalid session ID: " + sessionId);
        }

        try {
            // Provide the stdin data
            session.provideStdinData(data);

            // Create data for the success response
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("message", "Stdin data provided successfully");
            responseData.put("length", data.length());

            // Return a standardized success response
            return createSuccessResult(responseData);
        } catch (Exception e) {
            return createErrorResult("Failed to provide stdin data: " + e.getMessage());
        }
    }

    /**
     * Gets the stdout content from the emulator.
     *
     * @param sessionId the session ID
     * @return a map containing stdout content
     */
    public Map<String, Object> getStdoutContent(String sessionId) {
        EmulatorSession session = getSession(sessionId);
        if (session == null) {
            return createErrorResult("Invalid session ID: " + sessionId);
        }

        try {
            // Get the stdout content
            String stdout = session.getStdoutContent();

            // Create data for the success response
            Map<String, Object> data = new HashMap<>();
            data.put("content", stdout);
            data.put("length", stdout.length());

            // Return a standardized success response
            return createSuccessResult(data);
        } catch (Exception e) {
            return createErrorResult("Failed to get stdout content: " + e.getMessage());
        }
    }

    /**
     * Gets the stderr content from the emulator.
     *
     * @param sessionId the session ID
     * @return a map containing stderr content
     */
    public Map<String, Object> getStderrContent(String sessionId) {
        EmulatorSession session = getSession(sessionId);
        if (session == null) {
            return createErrorResult("Invalid session ID: " + sessionId);
        }

        try {
            // Get the stderr content
            String stderr = session.getStderrContent();

            // Create data for the success response
            Map<String, Object> data = new HashMap<>();
            data.put("content", stderr);
            data.put("length", stderr.length());

            // Return a standardized success response
            return createSuccessResult(data);
        } catch (Exception e) {
            return createErrorResult("Failed to get stderr content: " + e.getMessage());
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

            // Create data for the success response
            Map<String, Object> data = new HashMap<>();
            data.put("register", register);
            data.put("value", "0x" + registerValue.toString(16));
            data.put("decimal", registerValue.toString());

            // Return a standardized success response
            return createSuccessResult(data);
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

            // Create data for the success response
            Map<String, Object> data = new HashMap<>();
            data.put("register", register);
            data.put("value", "0x" + registerValue.toString(16));
            data.put("decimal", registerValue.toString());

            // Return a standardized success response
            return createSuccessResult(data);
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

                    // Try to read the register value, skip it if it fails
                    BigInteger value;
                    try {
                        value = emulator.readRegister(name);
                    } catch (Exception e) {
                        // Skip registers we can't read
                        continue;
                    }

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

            // Create data for the success response
            Map<String, Object> data = new HashMap<>();
            data.put("registers", registers);
            data.put("count", registers.size());

            // Return a standardized success response
            return createSuccessResult(data);
        } catch (Exception e) {
            return createErrorResult("Failed to get registers: " + e.getMessage());
        }
    }

    /**
     * Gets register change information.
     *
     * @param sessionId the session ID
     * @return a map containing register change information
     */
    public Map<String, Object> getRegisterChanges(String sessionId) {
        EmulatorSession session = getSession(sessionId);
        if (session == null) {
            return createErrorResult("Invalid session ID: " + sessionId);
        }

        try {
            // Get the register writes
            Map<String, Long> registerWrites = session.getRegisterWrites();

            // Create a list of register change objects
            List<Map<String, Object>> changes = new ArrayList<>();
            for (Map.Entry<String, Long> entry : registerWrites.entrySet()) {
                Map<String, Object> change = new HashMap<>();
                change.put("register", entry.getKey());
                change.put("value", "0x" + Long.toHexString(entry.getValue()));
                change.put("decimal", entry.getValue());
                changes.add(change);
            }

            // Create data for the success response
            Map<String, Object> data = new HashMap<>();
            data.put("changes", changes);
            data.put("count", changes.size());

            // Return a standardized success response
            return createSuccessResult(data);
        } catch (Exception e) {
            return createErrorResult("Failed to get register changes: " + e.getMessage());
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
            byte[] bytes = emulator.readMemory(addr, length);
            if (bytes == null) {
                return createErrorResult("Failed to read memory from address: " + address);
            }

            // Track the memory read
            session.trackMemoryRead(addr, bytes);

            // Get the memory data in the old format
            Map<String, Object> memoryData = getResult(address, length, bytes);
            
            // Return a standardized success response
            return createSuccessResult(memoryData);
        } catch (Exception e) {
            return createErrorResult("Failed to read memory: " + e.getMessage());
        }
    }

    /**
     * Creates a memory data result map without wrapping in success/error structure.
     * 
     * @param address the address as a string
     * @param length the length of data
     * @param bytes the byte array
     * @return a map containing memory data
     */
    private Map<String, Object> getResult(String address, int length, byte[] bytes) {
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
        data.put("address", address);
        data.put("length", length);
        data.put("hexValue", hex.toString());
        data.put("asciiValue", ascii.toString());
        return data;
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
            emulator.writeMemory(addr, bytes);
            
            // Since writeMemory() doesn't return success/failure, we assume it worked
            // if no exception was thrown

            // Track the memory write
            session.trackMemoryWrite(addr, bytes);

            // Create data for the success response
            Map<String, Object> data = new HashMap<>();
            data.put("address", address);
            data.put("bytesWritten", bytes.length);

            // Return a standardized success response
            return createSuccessResult(data);
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

            // Create data for the success response
            Map<String, Object> data = new HashMap<>();
            data.put("writes", writes);
            data.put("count", writes.size());
            data.put("totalBytes", memoryWrites.size());

            // Return a standardized success response
            return createSuccessResult(data);
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

            // Create data for the success response
            Map<String, Object> data = new HashMap<>();
            data.put("reads", reads);
            data.put("count", reads.size());
            data.put("totalBytes", memoryReads.size());

            // Return a standardized success response
            return createSuccessResult(data);
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

            // Create data for the success response
            Map<String, Object> data = new HashMap<>();
            data.put("tracking", enable);
            data.put("message", "Memory read tracking " + (enable ? "enabled" : "disabled"));

            // Return a standardized success response
            return createSuccessResult(data);
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

            // Create data for the success response
            Map<String, Object> data = new HashMap<>();
            data.put("tracking", enable);
            data.put("message", "Stack change tracking " + (enable ? "enabled" : "disabled"));

            // Return a standardized success response
            return createSuccessResult(data);
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

            // Create data for the success response
            Map<String, Object> data = new HashMap<>();
            data.put("stackTrace", stackTrace);
            data.put("count", stackTrace.size());

            // Return a standardized success response
            return createSuccessResult(data);
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
            byte[] bytes = emulator.readMemory(addr, len);
            if (bytes == null) {
                return createErrorResult("Failed to read memory from emulator");
            }

            // Write the memory to the program
            try {
                currentProgram.getMemory().setBytes(addr, bytes);
                int bytesWritten = bytes.length; // Assume all bytes were written

                // Create data for the success response
                Map<String, Object> data = new HashMap<>();
                data.put("bytesWritten", bytesWritten);
                data.put("fromAddress", fromAddress);
                data.put("toAddress", addr.add(bytesWritten - 1).toString());

                // Return a standardized success response
                return createSuccessResult(data);
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
     * Tracks stack changes for the current instruction.
     *
     * @param session The emulator session
     * @param instructionAddress The address of the current instruction
     */
    private void trackStackChanges(EmulatorSession session, Address instructionAddress) {
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
                Msg.warn(this, "Could not determine stack pointer register");
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

                    // Read memory values at this address
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
            Msg.error(this, "Error tracking stack changes", e);
        }
    }

    /**
     * Evaluates a conditional breakpoint expression.
     *
     * @param session The emulator session
     * @param condition The condition expression to evaluate
     * @return true if the condition is met, false otherwise
     */
    private boolean evaluateBreakpointCondition(EmulatorSession session, String condition) {
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
                            Msg.warn(this, "Cannot read memory at " + addr + ": " + e.getMessage());
                        }
                    }
                }
            }
            return false;
        } catch (Exception e) {
            Msg.error(this, "Error evaluating breakpoint condition: " + condition, e);
            return false;
        }
    }
}
