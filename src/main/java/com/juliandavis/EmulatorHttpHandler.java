package com.juliandavis;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.program.model.address.Address;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.lang.Register;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.math.BigInteger;

/**
 * HTTP handler for emulator-related endpoints in the GhidraMCPPlugin.
 * Provides endpoints for initializing, controlling, and retrieving state from the emulator.
 */
public class EmulatorHttpHandler {

    private final GhidraMCPPlugin plugin;
    
    // Track the current emulator session for each program
    private final Map<Program, String> programEmulatorSessions = new HashMap<>();
    
    public EmulatorHttpHandler(GhidraMCPPlugin plugin) {
        this.plugin = plugin;
    }
    
    /**
     * Registers emulator-related endpoints with the HTTP server
     */
    public void registerEndpoints() {
        // Get syscall information
        plugin.getServer().createContext("/emulator/getSyscallInfo", exchange -> {
            Map<String, String> params = plugin.parseQueryParams(exchange);
            String os = params.get("os");
            String processor = params.get("processor");
            String syscallNumberStr = params.get("syscallNumber");
            
            Map<String, Object> response = getSyscallInfo(os, processor, syscallNumberStr);
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Get all syscalls for an OS/processor combination
        plugin.getServer().createContext("/emulator/getAllSyscalls", exchange -> {
            Map<String, String> params = plugin.parseQueryParams(exchange);
            String os = params.get("os");
            String processor = params.get("processor");
            
            Map<String, Object> response = getAllSyscalls(os, processor);
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Check if syscall is I/O related
        plugin.getServer().createContext("/emulator/isIOSyscall", exchange -> {
            Map<String, String> params = plugin.parseQueryParams(exchange);
            String os = params.get("os");
            String processor = params.get("processor");
            String syscallNumberStr = params.get("syscallNumber");
            
            Map<String, Object> response = isIOSyscall(os, processor, syscallNumberStr);
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Check if OS is supported
        plugin.getServer().createContext("/emulator/isOSSupported", exchange -> {
            Map<String, String> params = plugin.parseQueryParams(exchange);
            String os = params.get("os");
            
            Map<String, Object> response = isOSSupported(os);
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Check if OS/processor combination is supported
        plugin.getServer().createContext("/emulator/isArchSupported", exchange -> {
            Map<String, String> params = plugin.parseQueryParams(exchange);
            String os = params.get("os");
            String processor = params.get("processor");
            
            Map<String, Object> response = isArchSupported(os, processor);
            plugin.sendJsonResponse(exchange, response);
        });
        // Get architecture information
        plugin.getServer().createContext("/emulator/getArchitectureInfo", exchange -> {
            Map<String, Object> response = getArchitectureInfo();
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Initialize emulator session
        plugin.getServer().createContext("/emulator/initialize", exchange -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            String addressStr = params.get("address");
            boolean writeTracking = Boolean.parseBoolean(params.getOrDefault("writeTracking", "true"));
            
            Map<String, Object> response = initializeEmulator(addressStr, writeTracking);
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Step emulator
        plugin.getServer().createContext("/emulator/step", exchange -> {
            Map<String, Object> response = stepEmulator();
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Run emulator
        plugin.getServer().createContext("/emulator/run", exchange -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            int maxSteps = Integer.parseInt(params.getOrDefault("maxSteps", "1000"));
            boolean stopOnBreakpoint = Boolean.parseBoolean(params.getOrDefault("stopOnBreakpoint", "true"));
            String stopAddress = params.get("stopAddress");
            
            Map<String, Object> response = runEmulator(maxSteps, stopOnBreakpoint, stopAddress);
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Get emulator state
        plugin.getServer().createContext("/emulator/getState", exchange -> {
            Map<String, Object> response = getEmulatorState();
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Get memory writes
        plugin.getServer().createContext("/emulator/getWrites", exchange -> {
            Map<String, Object> response = getMemoryWrites();
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Import memory from emulator to program
        plugin.getServer().createContext("/emulator/importMemory", exchange -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            String fromAddress = params.get("fromAddress");
            String length = params.get("length");
            
            Map<String, Object> response = importMemoryToProgram(fromAddress, length);
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Set breakpoint
        plugin.getServer().createContext("/emulator/setBreakpoint", exchange -> {
            String addressStr = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            Map<String, Object> response = setBreakpoint(addressStr);
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Clear breakpoint
        plugin.getServer().createContext("/emulator/clearBreakpoint", exchange -> {
            String addressStr = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            Map<String, Object> response = clearBreakpoint(addressStr);
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Clear all breakpoints
        plugin.getServer().createContext("/emulator/clearAllBreakpoints", exchange -> {
            Map<String, Object> response = clearAllBreakpoints();
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Get breakpoints
        plugin.getServer().createContext("/emulator/getBreakpoints", exchange -> {
            Map<String, Object> response = getBreakpoints();
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Reset emulator
        plugin.getServer().createContext("/emulator/reset", exchange -> {
            Map<String, Object> response = resetEmulator();
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Set conditional breakpoint
        plugin.getServer().createContext("/emulator/setConditionalBreakpoint", exchange -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            String addressStr = params.get("address");
            String condition = params.get("condition");
            
            Map<String, Object> response = setConditionalBreakpoint(addressStr, condition);
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Clear conditional breakpoint
        plugin.getServer().createContext("/emulator/clearConditionalBreakpoint", exchange -> {
            String addressStr = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            Map<String, Object> response = clearConditionalBreakpoint(addressStr);
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Get conditional breakpoints
        plugin.getServer().createContext("/emulator/getConditionalBreakpoints", exchange -> {
            Map<String, Object> response = getConditionalBreakpoints();
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Set register value
        plugin.getServer().createContext("/emulator/setRegister", exchange -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            String register = params.get("register");
            String value = params.get("value");
            
            Map<String, Object> response = setRegisterValue(register, value);
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Get register value
        plugin.getServer().createContext("/emulator/getRegister", exchange -> {
            Map<String, String> params = plugin.parseQueryParams(exchange);
            String register = params.get("register");
            
            Map<String, Object> response = getRegisterValue(register);
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Get all register names and values
        plugin.getServer().createContext("/emulator/getRegisters", exchange -> {
            Map<String, Object> response = getRegisterNames();
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Write memory
        plugin.getServer().createContext("/emulator/writeMemory", exchange -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            String address = params.get("address");
            String bytesHex = params.get("bytes");
            
            Map<String, Object> response = writeMemory(address, bytesHex);
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Read memory
        plugin.getServer().createContext("/emulator/readMemory", exchange -> {
            Map<String, String> params = plugin.parseQueryParams(exchange);
            String address = params.get("address");
            int length = Integer.parseInt(params.getOrDefault("length", "16"));
            
            Map<String, Object> response = readMemory(address, length);
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Enable/disable memory read tracking
        plugin.getServer().createContext("/emulator/setMemoryReadTracking", exchange -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            boolean enable = Boolean.parseBoolean(params.getOrDefault("enable", "true"));
            
            Map<String, Object> response = setMemoryReadTracking(enable);
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Get memory reads
        plugin.getServer().createContext("/emulator/getReads", exchange -> {
            Map<String, Object> response = getMemoryReads();
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Enable/disable stack change tracking
        plugin.getServer().createContext("/emulator/setStackChangeTracking", exchange -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            boolean enable = Boolean.parseBoolean(params.getOrDefault("enable", "true"));
            
            Map<String, Object> response = setStackChangeTracking(enable);
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Get stack trace
        plugin.getServer().createContext("/emulator/getStackTrace", exchange -> {
            Map<String, Object> response = getStackTrace();
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Get register changes
        plugin.getServer().createContext("/emulator/getRegisterChanges", exchange -> {
            Map<String, Object> response = getRegisterChanges();
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Get stdout content
        plugin.getServer().createContext("/emulator/getStdout", exchange -> {
            Map<String, Object> response = getStdoutContent();
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Get stderr content
        plugin.getServer().createContext("/emulator/getStderr", exchange -> {
            Map<String, Object> response = getStderrContent();
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Provide stdin data
        plugin.getServer().createContext("/emulator/provideStdin", exchange -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            String data = params.get("data");
            Map<String, Object> response = provideStdinData(data);
            plugin.sendJsonResponse(exchange, response);
        });
        
        // Dispose emulator session
        plugin.getServer().createContext("/emulator/dispose", exchange -> {
            Map<String, Object> response = disposeEmulatorSession();
            plugin.sendJsonResponse(exchange, response);
        });
    }
    
    /**
     * Helper method to retrieve and validate the emulator session for the current program.
     * 
     * @return The validated EmulatorSession or null if validation fails
     */
    private EmulatorService.EmulatorSession getValidatedSession() {
        // Get the current program
        Program program = plugin.getCurrentProgram();
        if (program == null) {
            return null;
        }
        
        // Get session for current program
        String sessionId = programEmulatorSessions.get(program);
        if (sessionId == null) {
            return null;
        }
        
        // Get and validate the session
        return EmulatorService.getSession(sessionId);
    }
    
    /**
     * Helper method to create an error response with a specific message
     * 
     * @param message The error message
     * @return A Map containing the error response
     */
    private Map<String, Object> createErrorResponse(String message) {
        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("error", message);
        return response;
    }
    
    /**
     * Initialize the emulator at the specified address
     */
    private Map<String, Object> initializeEmulator(String addressStr, boolean writeTracking) {
        Program program = plugin.getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        Map<String, Object> response = new HashMap<>();
        
        try {
            // Check if there's already a session for this program
            String existingSessionId = programEmulatorSessions.get(program);
            EmulatorService.EmulatorSession session;
            
            if (existingSessionId != null) {
                session = EmulatorService.getSession(existingSessionId);
                
                // If a session exists but is invalid, properly dispose it before creating a new one
                EmulatorService.disposeSession(existingSessionId);
                programEmulatorSessions.remove(program);
                if (session == null) {
                    // Try to dispose the invalid session explicitly
                    Msg.info(this, "Disposed invalid emulator session: " + existingSessionId);
                } else {
                    // Properly dispose the existing valid session before creating a new one
                    // This ensures resources are properly cleaned up
                    Msg.info(this, "Disposed existing emulator session before initialization: " + existingSessionId);
                }
            }
            
            // Create a new session
            session = EmulatorService.createSession(program);
            programEmulatorSessions.put(program, session.getId());
            
            // Initialize emulator with tracking options
            boolean success = EmulatorService.initializeEmulator(session, addressStr, writeTracking);
            
            // Configure advanced tracking options (disabled by default)
            session.setTrackMemoryReads(false);
            session.setTrackStackChanges(false);
            
            if (success) {
                response.put("success", true);
                response.put("sessionId", session.getId());
                response.put("startAddress", addressStr);
                response.put("message", "Emulator initialized successfully");
                response.put("writeTracking", writeTracking);
                response.put("readTracking", false);
                response.put("stackTracking", false);
            } else {
                response.put("success", false);
                response.put("error", session.getLastError() != null ? 
                    session.getLastError() : "Failed to initialize emulator");
            }
            
        } catch (Exception e) {
            Msg.error(this, "Error initializing emulator", e);
            response.put("success", false);
            response.put("error", "Error initializing emulator: " + e.getMessage());
        }
        
        return response;
    }
    
    /**
     * Step the emulator forward by one instruction
     */
    private Map<String, Object> stepEmulator() {
        EmulatorService.EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        return EmulatorService.stepEmulator(session);
    }
    
    /**
     * Run the emulator until a condition is met
     */
    private Map<String, Object> runEmulator(int maxSteps, boolean stopOnBreakpoint, String stopAddress) {
        EmulatorService.EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        return EmulatorService.runEmulator(session, maxSteps, stopOnBreakpoint, stopAddress);
    }
    
    /**
     * Get the current emulator state
     */
    private Map<String, Object> getEmulatorState() {
        EmulatorService.EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        return EmulatorService.getEmulatorState(session);
    }
    
    /**
     * Get memory writes from the emulator
     */
    private Map<String, Object> getMemoryWrites() {
        EmulatorService.EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        return EmulatorService.getMemoryWrites(session);
    }
    
    /**
     * Import memory from emulator to program
     */
    private Map<String, Object> importMemoryToProgram(String fromAddress, String length) {
        EmulatorService.EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        return EmulatorService.importMemoryToProgram(session, fromAddress, length);
    }
    
    /**
     * Set a breakpoint at the specified address
     */
    private Map<String, Object> setBreakpoint(String addressStr) {
        EmulatorService.EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        return EmulatorService.setBreakpoint(session, addressStr);
    }
    
    /**
     * Clear a breakpoint at the specified address
     */
    private Map<String, Object> clearBreakpoint(String addressStr) {
        EmulatorService.EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        return EmulatorService.clearBreakpoint(session, addressStr);
    }
    
    /**
     * Get all breakpoints
     */
    private Map<String, Object> getBreakpoints() {
        EmulatorService.EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        return EmulatorService.getBreakpoints(session);
    }
    
    /**
     * Reset the emulator to its initial state
     */
    private Map<String, Object> resetEmulator() {
        EmulatorService.EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        return EmulatorService.resetEmulator(session);
    }
    
    /**
     * Set a conditional breakpoint
     */
    private Map<String, Object> setConditionalBreakpoint(String addressStr, String condition) {
        EmulatorService.EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        return EmulatorService.setConditionalBreakpoint(session, addressStr, condition);
    }
    
    /**
     * Get conditional breakpoints
     */
    private Map<String, Object> getConditionalBreakpoints() {
        EmulatorService.EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        return EmulatorService.getConditionalBreakpoints(session);
    }
    
    /**
     * Set register value
     */
    private Map<String, Object> setRegisterValue(String registerName, String value) {
        EmulatorService.EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        return EmulatorService.setRegisterValue(session, registerName, value);
    }
    
    /**
     * Get register value
     */
    private Map<String, Object> getRegisterValue(String registerName) {
        EmulatorService.EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        return EmulatorService.getRegisterValue(session, registerName);
    }
    
    /**
     * Get register names and values
     */
    private Map<String, Object> getRegisterNames() {
        EmulatorService.EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        return EmulatorService.getRegisterNames(session);
    }
    
    /**
     * Write memory
     */
    private Map<String, Object> writeMemory(String addressStr, String bytesHex) {
        EmulatorService.EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        return EmulatorService.writeMemory(session, addressStr, bytesHex);
    }
    
    /**
     * Read memory
     */
    private Map<String, Object> readMemory(String addressStr, int length) {
        EmulatorService.EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        return EmulatorService.readMemory(session, addressStr, length);
    }
    
    /**
     * Set memory read tracking
     */
    private Map<String, Object> setMemoryReadTracking(boolean enable) {
        EmulatorService.EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        return EmulatorService.setMemoryReadTracking(session, enable);
    }
    
    /**
     * Get memory reads
     */
    private Map<String, Object> getMemoryReads() {
        EmulatorService.EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        return EmulatorService.getMemoryReads(session);
    }
    
    /**
     * Set stack change tracking
     */
    private Map<String, Object> setStackChangeTracking(boolean enable) {
        EmulatorService.EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        return EmulatorService.setStackChangeTracking(session, enable);
    }
    
    /**
     * Get stack trace
     */
    private Map<String, Object> getStackTrace() {
        EmulatorService.EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        return EmulatorService.getStackTrace(session);
    }
    
    /**
     * Clear all breakpoints
     */
    private Map<String, Object> clearAllBreakpoints() {
        EmulatorService.EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        // Clear all breakpoints
        session.clearBreakpoints();
        
        Map<String, Object> result = new HashMap<>();
        result.put("success", true);
        result.put("message", "All breakpoints cleared");
        return result;
    }
    
    /**
     * Clear a conditional breakpoint at the specified address
     */
    private Map<String, Object> clearConditionalBreakpoint(String addressStr) {
        EmulatorService.EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        try {
            Program program = session.getProgram();
            Address address = program.getAddressFactory().getAddress(addressStr);
            
            if (address == null) {
                return createErrorResponse("Invalid address: " + addressStr);
            }
            
            boolean removed = session.removeConditionalBreakpoint(address);
            
            Map<String, Object> result = new HashMap<>();
            result.put("success", true);
            result.put("address", address.toString());
            result.put("removed", removed);
            if (!removed) {
                result.put("message", "No conditional breakpoint exists at this address");
            }
            
            return result;
        } catch (Exception e) {
            ghidra.util.Msg.error(this, "Error clearing conditional breakpoint", e);
            return createErrorResponse("Error clearing conditional breakpoint: " + e.getMessage());
        }
    }
    
    /**
     * Get register changes that occurred during emulation
     */
    private Map<String, Object> getRegisterChanges() {
        EmulatorService.EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        try {
            // Get register write history from the session
            Map<String, Long> registerWrites = session.getRegisterWrites();
            
            // Get current register state for comparison
            EmulatorHelper emulator = session.getEmulator();
            Program program = session.getProgram();
            
            List<Map<String, Object>> changes = new ArrayList<>();
            
            // Convert to a list of register changes with additional information
            for (Map.Entry<String, Long> entry : registerWrites.entrySet()) {
                String regName = entry.getKey();
                Long trackedValue = entry.getValue();
                
                Map<String, Object> regChange = new HashMap<>();
                regChange.put("register", regName);
                regChange.put("value", String.format("0x%x", trackedValue));
                regChange.put("decimalValue", trackedValue);
                
                // Try to get current value for comparison
                try {
                    BigInteger currentValue = emulator.readRegister(regName);
                    
                    // Check if current value differs from tracked value
                    boolean changed = !currentValue.equals(BigInteger.valueOf(trackedValue));
                    regChange.put("currentValue", currentValue.toString(16));
                    regChange.put("currentDecimalValue", currentValue.toString());
                    regChange.put("hasChanged", changed);
                    
                    // Add special flags for important registers
                    try {
                        Register reg = program.getLanguage().getRegister(regName);
                        if (reg != null) {
                            if (reg.equals(emulator.getPCRegister())) {
                                regChange.put("isPC", true);
                            }
                            if (reg.equals(emulator.getStackPointerRegister())) {
                                regChange.put("isSP", true);
                            }
                        }
                    } catch (Exception e) {
                        // Ignore errors in getting register metadata
                    }
                } catch (Exception e) {
                    // If we can't read current value, just include tracked value
                    regChange.put("hasChanged", false);
                }
                
                changes.add(regChange);
            }
            
            // Sort by register name for consistency
            changes.sort(Comparator.comparing(m -> ((String)m.get("register"))));
            
            Map<String, Object> result = new HashMap<>();
            result.put("success", true);
            result.put("changes", changes);
            result.put("count", changes.size());
            
            // Include timestamp for when this data was fetched
            result.put("timestamp", System.currentTimeMillis());
            
            return result;
        } catch (Exception e) {
            ghidra.util.Msg.error(this, "Error getting register changes", e);
            return createErrorResponse("Error getting register changes: " + e.getMessage());
        }
    }
    
    /**
     * Dispose of the current emulator session
     */
    private Map<String, Object> disposeEmulatorSession() {
        Program program = plugin.getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        String sessionId = programEmulatorSessions.get(program);
        if (sessionId == null) {
            return createErrorResponse("No emulator session for current program");
        }
        
        boolean disposed = EmulatorService.disposeSession(sessionId);
        if (disposed) {
            programEmulatorSessions.remove(program);
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("success", disposed);
        result.put("message", disposed ? 
            "Emulator session disposed successfully" : 
            "Failed to dispose emulator session");
        
        return result;
    }
    
    /**
     * Get architecture-specific information for the current program.
     * This information includes processor name, endianness, and stack growth direction.
     * 
     * @return Map containing architecture information
     */
    private Map<String, Object> getArchitectureInfo() {
        Program program = plugin.getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        Map<String, Object> result = new HashMap<>();
        
        try {
            // Create a temporary EmulatorHelper to access architecture information
            EmulatorHelper emulator = new EmulatorHelper(program);
            ArchitectureHelper archHelper = new ArchitectureHelper(program, emulator);
            
            // Get architecture information
            String processorName = archHelper.getProcessorName();
            boolean isBigEndian = archHelper.isBigEndian();
            int stackGrowthDirection = archHelper.getStackGrowthDirection();
            int pointerSize = archHelper.getPointerSize();
            String pcRegisterName = archHelper.getProgramCounterRegisterName();
            String spRegisterName = archHelper.getStackPointerRegisterName();
            
            // Create the response
            result.put("success", true);
            result.put("processorName", processorName);
            result.put("isBigEndian", isBigEndian);
            result.put("stackGrowthDirection", stackGrowthDirection);
            result.put("stackGrowthDirectionDesc", stackGrowthDirection > 0 ? "upward" : "downward");
            result.put("pointerSize", pointerSize);
            result.put("programCounterRegister", pcRegisterName);
            result.put("stackPointerRegister", spRegisterName);
            
            // Add information about the language
            result.put("languageName", program.getLanguage().getLanguageDescription().getDescription());
            result.put("languageId", program.getLanguage().getLanguageID().getIdAsString());
            result.put("addressSize", program.getAddressFactory().getDefaultAddressSpace().getSize());
            
            // Add syscall support information
            String os = SyscallMappings.determineOS(program);
            result.put("detectedOS", os);
            result.put("osSupported", SyscallMappings.isOSSupported(os));
            result.put("archSupported", SyscallMappings.isSupported(os, processorName));
            
            // Get syscalls count if supported
            if (SyscallMappings.isSupported(os, processorName)) {
                Map<Integer, SyscallMappings.SyscallInfo> allSyscalls = SyscallMappings.getAllSyscalls(os, processorName);
                result.put("syscallsCount", allSyscalls.size());
            }
            
            // Clean up resources
            emulator.dispose();
            
        } catch (Exception e) {
            ghidra.util.Msg.error(this, "Error getting architecture information", e);
            return createErrorResponse("Error getting architecture information: " + e.getMessage());
        }
        
        return result;
    }
    
    /**
     * Get the current stdout content
     */
    private Map<String, Object> getStdoutContent() {
        EmulatorService.EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("success", true);
        result.put("stdoutContent", session.getStdoutContent());
        return result;
    }
    
    /**
     * Get the current stderr content
     */
    private Map<String, Object> getStderrContent() {
        EmulatorService.EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("success", true);
        result.put("stderrContent", session.getStderrContent());
        return result;
    }
    
    /**
     * Provide data to stdin
     */
    private Map<String, Object> provideStdinData(String data) {
        EmulatorService.EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        if (data == null) {
            data = "";
        }
        
        session.provideStdinData(data);
        
        Map<String, Object> result = new HashMap<>();
        result.put("success", true);
        result.put("message", "Input data provided to stdin");
        result.put("dataLength", data.length());
        return result;
    }
    
    /**
     * Get information about a specific syscall
     * 
     * @param os Operating system (e.g., "linux", "macos", "windows")
     * @param processor Processor architecture (e.g., "x86", "ARM")
     * @param syscallNumberStr Syscall number as a string
     * @return Map containing syscall information
     */
    private Map<String, Object> getSyscallInfo(String os, String processor, String syscallNumberStr) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            // Check for missing parameters
            if (os == null || processor == null || syscallNumberStr == null) {
                return createErrorResponse("Required parameters: os, processor, syscallNumber");
            }
            
            // Parse syscall number
            int syscallNumber;
            try {
                // Handle both decimal and hex format
                if (syscallNumberStr.startsWith("0x")) {
                    syscallNumber = Integer.parseInt(syscallNumberStr.substring(2), 16);
                } else {
                    syscallNumber = Integer.parseInt(syscallNumberStr);
                }
            } catch (NumberFormatException e) {
                return createErrorResponse("Invalid syscall number: " + syscallNumberStr);
            }
            
            // Use SyscallMappings to get information
            SyscallMappings.SyscallInfo info = SyscallMappings.getSyscallInfo(os, processor, syscallNumber);
            
            if (info == null) {
                result.put("success", false);
                result.put("message", "Syscall not found for " + os + "/" + processor + ": " + syscallNumber);
                return result;
            }
            
            result.put("success", true);
            result.put("name", info.getName());
            result.put("paramCount", info.getParamCount());
            result.put("paramTypes", info.getParamTypes());
            result.put("returnType", info.getReturnType());
            result.put("description", info.getDescription());
            result.put("isIO", SyscallMappings.isIOSyscall(os, processor, syscallNumber));
            
            return result;
        } catch (Exception e) {
            ghidra.util.Msg.error(this, "Error getting syscall info", e);
            return createErrorResponse("Error getting syscall info: " + e.getMessage());
        }
    }
    
    /**
     * Get all syscalls for an OS/processor combination
     * 
     * @param os Operating system (e.g., "linux", "macos", "windows")
     * @param processor Processor architecture (e.g., "x86", "ARM")
     * @return Map containing all syscalls
     */
    private Map<String, Object> getAllSyscalls(String os, String processor) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            // Check for missing parameters
            if (os == null || processor == null) {
                return createErrorResponse("Required parameters: os, processor");
            }
            
            // Use SyscallMappings to get all syscalls
            Map<Integer, SyscallMappings.SyscallInfo> allSyscalls = SyscallMappings.getAllSyscalls(os, processor);
            
            if (allSyscalls.isEmpty()) {
                result.put("success", false);
                result.put("message", "No syscalls found for " + os + "/" + processor);
                return result;
            }
            
            // Convert to a more JSON-friendly format
            List<Map<String, Object>> syscallList = new ArrayList<>();
            for (Map.Entry<Integer, SyscallMappings.SyscallInfo> entry : allSyscalls.entrySet()) {
                Integer number = entry.getKey();
                SyscallMappings.SyscallInfo info = entry.getValue();
                
                Map<String, Object> syscallInfo = new HashMap<>();
                syscallInfo.put("number", number);
                syscallInfo.put("name", info.getName());
                syscallInfo.put("paramCount", info.getParamCount());
                syscallInfo.put("paramTypes", info.getParamTypes());
                syscallInfo.put("returnType", info.getReturnType());
                syscallInfo.put("description", info.getDescription());
                syscallInfo.put("isIO", SyscallMappings.isIOSyscall(os, processor, number));
                
                syscallList.add(syscallInfo);
            }
            
            // Sort by syscall number for consistency
            syscallList.sort(Comparator.comparing(m -> ((Integer)m.get("number"))));
            
            result.put("success", true);
            result.put("syscalls", syscallList);
            result.put("count", syscallList.size());
            
            return result;
        } catch (Exception e) {
            ghidra.util.Msg.error(this, "Error getting all syscalls", e);
            return createErrorResponse("Error getting all syscalls: " + e.getMessage());
        }
    }
    
    /**
     * Check if a syscall is I/O related
     * 
     * @param os Operating system (e.g., "linux", "macos", "windows")
     * @param processor Processor architecture (e.g., "x86", "ARM")
     * @param syscallNumberStr Syscall number as a string
     * @return Map containing the result
     */
    private Map<String, Object> isIOSyscall(String os, String processor, String syscallNumberStr) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            // Check for missing parameters
            if (os == null || processor == null || syscallNumberStr == null) {
                return createErrorResponse("Required parameters: os, processor, syscallNumber");
            }
            
            // Parse syscall number
            int syscallNumber;
            try {
                // Handle both decimal and hex format
                if (syscallNumberStr.startsWith("0x")) {
                    syscallNumber = Integer.parseInt(syscallNumberStr.substring(2), 16);
                } else {
                    syscallNumber = Integer.parseInt(syscallNumberStr);
                }
            } catch (NumberFormatException e) {
                return createErrorResponse("Invalid syscall number: " + syscallNumberStr);
            }
            
            // Use SyscallMappings to check if I/O related
            boolean isIO = SyscallMappings.isIOSyscall(os, processor, syscallNumber);
            
            result.put("success", true);
            result.put("isIO", isIO);
            
            // Get additional info about the syscall
            SyscallMappings.SyscallInfo info = SyscallMappings.getSyscallInfo(os, processor, syscallNumber);
            if (info != null) {
                result.put("name", info.getName());
                result.put("found", true);
            } else {
                result.put("found", false);
            }
            
            return result;
        } catch (Exception e) {
            ghidra.util.Msg.error(this, "Error checking if syscall is I/O related", e);
            return createErrorResponse("Error checking if syscall is I/O related: " + e.getMessage());
        }
    }
    
    /**
     * Check if an OS is supported
     * 
     * @param os Operating system (e.g., "linux", "macos", "windows")
     * @return Map containing the result
     */
    private Map<String, Object> isOSSupported(String os) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            // Check for missing parameter
            if (os == null) {
                return createErrorResponse("Required parameter: os");
            }
            
            // Use SyscallMappings to check if OS is supported
            boolean isSupported = SyscallMappings.isOSSupported(os);
            
            result.put("success", true);
            result.put("os", os);
            result.put("isSupported", isSupported);
            
            return result;
        } catch (Exception e) {
            ghidra.util.Msg.error(this, "Error checking if OS is supported", e);
            return createErrorResponse("Error checking if OS is supported: " + e.getMessage());
        }
    }
    
    /**
     * Check if an OS/processor combination is supported
     * 
     * @param os Operating system (e.g., "linux", "macos", "windows")
     * @param processor Processor architecture (e.g., "x86", "ARM")
     * @return Map containing the result
     */
    private Map<String, Object> isArchSupported(String os, String processor) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            // Check for missing parameters
            if (os == null || processor == null) {
                return createErrorResponse("Required parameters: os, processor");
            }
            
            // Use SyscallMappings to check if OS/processor combination is supported
            boolean isSupported = SyscallMappings.isSupported(os, processor);
            
            result.put("success", true);
            result.put("os", os);
            result.put("processor", processor);
            result.put("isSupported", isSupported);
            
            return result;
        } catch (Exception e) {
            ghidra.util.Msg.error(this, "Error checking if arch is supported", e);
            return createErrorResponse("Error checking if arch is supported: " + e.getMessage());
        }
    }
}