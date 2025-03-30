package com.juliandavis;

import com.sun.net.httpserver.HttpExchange;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

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
            String sessionId = programEmulatorSessions.get(program);
            EmulatorService.EmulatorSession session = null;
            
            if (sessionId != null) {
                session = EmulatorService.getSession(sessionId);
            }
            
            // If no valid session exists, create a new one
            if (session == null) {
                session = EmulatorService.createSession(program);
                programEmulatorSessions.put(program, session.getId());
            }
            
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
        Program program = plugin.getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        // Get session for current program
        String sessionId = programEmulatorSessions.get(program);
        if (sessionId == null) {
            return createErrorResponse("Emulator not initialized for current program");
        }
        
        EmulatorService.EmulatorSession session = EmulatorService.getSession(sessionId);
        if (session == null) {
            return createErrorResponse("Invalid emulator session");
        }
        
        return EmulatorService.stepEmulator(session);
    }
    
    /**
     * Run the emulator until a condition is met
     */
    private Map<String, Object> runEmulator(int maxSteps, boolean stopOnBreakpoint, String stopAddress) {
        Program program = plugin.getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        // Get session for current program
        String sessionId = programEmulatorSessions.get(program);
        if (sessionId == null) {
            return createErrorResponse("Emulator not initialized for current program");
        }
        
        EmulatorService.EmulatorSession session = EmulatorService.getSession(sessionId);
        if (session == null) {
            return createErrorResponse("Invalid emulator session");
        }
        
        return EmulatorService.runEmulator(session, maxSteps, stopOnBreakpoint, stopAddress);
    }
    
    /**
     * Get the current emulator state
     */
    private Map<String, Object> getEmulatorState() {
        Program program = plugin.getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        // Get session for current program
        String sessionId = programEmulatorSessions.get(program);
        if (sessionId == null) {
            return createErrorResponse("Emulator not initialized for current program");
        }
        
        EmulatorService.EmulatorSession session = EmulatorService.getSession(sessionId);
        if (session == null) {
            return createErrorResponse("Invalid emulator session");
        }
        
        return EmulatorService.getEmulatorState(session);
    }
    
    /**
     * Get memory writes from the emulator
     */
    private Map<String, Object> getMemoryWrites() {
        Program program = plugin.getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        // Get session for current program
        String sessionId = programEmulatorSessions.get(program);
        if (sessionId == null) {
            return createErrorResponse("Emulator not initialized for current program");
        }
        
        EmulatorService.EmulatorSession session = EmulatorService.getSession(sessionId);
        if (session == null) {
            return createErrorResponse("Invalid emulator session");
        }
        
        return EmulatorService.getMemoryWrites(session);
    }
    
    /**
     * Import memory from emulator to program
     */
    private Map<String, Object> importMemoryToProgram(String fromAddress, String length) {
        Program program = plugin.getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        // Get session for current program
        String sessionId = programEmulatorSessions.get(program);
        if (sessionId == null) {
            return createErrorResponse("Emulator not initialized for current program");
        }
        
        EmulatorService.EmulatorSession session = EmulatorService.getSession(sessionId);
        if (session == null) {
            return createErrorResponse("Invalid emulator session");
        }
        
        return EmulatorService.importMemoryToProgram(session, fromAddress, length);
    }
    
    /**
     * Set a breakpoint at the specified address
     */
    private Map<String, Object> setBreakpoint(String addressStr) {
        Program program = plugin.getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        // Get session for current program
        String sessionId = programEmulatorSessions.get(program);
        if (sessionId == null) {
            return createErrorResponse("Emulator not initialized for current program");
        }
        
        EmulatorService.EmulatorSession session = EmulatorService.getSession(sessionId);
        if (session == null) {
            return createErrorResponse("Invalid emulator session");
        }
        
        return EmulatorService.setBreakpoint(session, addressStr);
    }
    
    /**
     * Clear a breakpoint at the specified address
     */
    private Map<String, Object> clearBreakpoint(String addressStr) {
        Program program = plugin.getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        // Get session for current program
        String sessionId = programEmulatorSessions.get(program);
        if (sessionId == null) {
            return createErrorResponse("Emulator not initialized for current program");
        }
        
        EmulatorService.EmulatorSession session = EmulatorService.getSession(sessionId);
        if (session == null) {
            return createErrorResponse("Invalid emulator session");
        }
        
        return EmulatorService.clearBreakpoint(session, addressStr);
    }
    
    /**
     * Get all breakpoints
     */
    private Map<String, Object> getBreakpoints() {
        Program program = plugin.getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        // Get session for current program
        String sessionId = programEmulatorSessions.get(program);
        if (sessionId == null) {
            return createErrorResponse("Emulator not initialized for current program");
        }
        
        EmulatorService.EmulatorSession session = EmulatorService.getSession(sessionId);
        if (session == null) {
            return createErrorResponse("Invalid emulator session");
        }
        
        return EmulatorService.getBreakpoints(session);
    }
    
    /**
     * Reset the emulator to its initial state
     */
    private Map<String, Object> resetEmulator() {
        Program program = plugin.getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        // Get session for current program
        String sessionId = programEmulatorSessions.get(program);
        if (sessionId == null) {
            return createErrorResponse("Emulator not initialized for current program");
        }
        
        EmulatorService.EmulatorSession session = EmulatorService.getSession(sessionId);
        if (session == null) {
            return createErrorResponse("Invalid emulator session");
        }
        
        return EmulatorService.resetEmulator(session);
    }
    
    /**
     * Create an error response
     */
    private Map<String, Object> createErrorResponse(String message) {
        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("error", message);
        return response;
    }
    
    /**
     * Set a conditional breakpoint
     */
    private Map<String, Object> setConditionalBreakpoint(String addressStr, String condition) {
        Program program = plugin.getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        // Get session for current program
        String sessionId = programEmulatorSessions.get(program);
        if (sessionId == null) {
            return createErrorResponse("Emulator not initialized for current program");
        }
        
        EmulatorService.EmulatorSession session = EmulatorService.getSession(sessionId);
        if (session == null) {
            return createErrorResponse("Invalid emulator session");
        }
        
        return EmulatorService.setConditionalBreakpoint(session, addressStr, condition);
    }
    
    /**
     * Get conditional breakpoints
     */
    private Map<String, Object> getConditionalBreakpoints() {
        Program program = plugin.getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        // Get session for current program
        String sessionId = programEmulatorSessions.get(program);
        if (sessionId == null) {
            return createErrorResponse("Emulator not initialized for current program");
        }
        
        EmulatorService.EmulatorSession session = EmulatorService.getSession(sessionId);
        if (session == null) {
            return createErrorResponse("Invalid emulator session");
        }
        
        return EmulatorService.getConditionalBreakpoints(session);
    }
    
    /**
     * Set register value
     */
    private Map<String, Object> setRegisterValue(String registerName, String value) {
        Program program = plugin.getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        // Get session for current program
        String sessionId = programEmulatorSessions.get(program);
        if (sessionId == null) {
            return createErrorResponse("Emulator not initialized for current program");
        }
        
        EmulatorService.EmulatorSession session = EmulatorService.getSession(sessionId);
        if (session == null) {
            return createErrorResponse("Invalid emulator session");
        }
        
        return EmulatorService.setRegisterValue(session, registerName, value);
    }
    
    /**
     * Get register value
     */
    private Map<String, Object> getRegisterValue(String registerName) {
        Program program = plugin.getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        // Get session for current program
        String sessionId = programEmulatorSessions.get(program);
        if (sessionId == null) {
            return createErrorResponse("Emulator not initialized for current program");
        }
        
        EmulatorService.EmulatorSession session = EmulatorService.getSession(sessionId);
        if (session == null) {
            return createErrorResponse("Invalid emulator session");
        }
        
        return EmulatorService.getRegisterValue(session, registerName);
    }
    
    /**
     * Get register names and values
     */
    private Map<String, Object> getRegisterNames() {
        Program program = plugin.getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        // Get session for current program
        String sessionId = programEmulatorSessions.get(program);
        if (sessionId == null) {
            return createErrorResponse("Emulator not initialized for current program");
        }
        
        EmulatorService.EmulatorSession session = EmulatorService.getSession(sessionId);
        if (session == null) {
            return createErrorResponse("Invalid emulator session");
        }
        
        return EmulatorService.getRegisterNames(session);
    }
    
    /**
     * Write memory
     */
    private Map<String, Object> writeMemory(String addressStr, String bytesHex) {
        Program program = plugin.getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        // Get session for current program
        String sessionId = programEmulatorSessions.get(program);
        if (sessionId == null) {
            return createErrorResponse("Emulator not initialized for current program");
        }
        
        EmulatorService.EmulatorSession session = EmulatorService.getSession(sessionId);
        if (session == null) {
            return createErrorResponse("Invalid emulator session");
        }
        
        return EmulatorService.writeMemory(session, addressStr, bytesHex);
    }
    
    /**
     * Read memory
     */
    private Map<String, Object> readMemory(String addressStr, int length) {
        Program program = plugin.getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        // Get session for current program
        String sessionId = programEmulatorSessions.get(program);
        if (sessionId == null) {
            return createErrorResponse("Emulator not initialized for current program");
        }
        
        EmulatorService.EmulatorSession session = EmulatorService.getSession(sessionId);
        if (session == null) {
            return createErrorResponse("Invalid emulator session");
        }
        
        return EmulatorService.readMemory(session, addressStr, length);
    }
    
    /**
     * Set memory read tracking
     */
    private Map<String, Object> setMemoryReadTracking(boolean enable) {
        Program program = plugin.getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        // Get session for current program
        String sessionId = programEmulatorSessions.get(program);
        if (sessionId == null) {
            return createErrorResponse("Emulator not initialized for current program");
        }
        
        EmulatorService.EmulatorSession session = EmulatorService.getSession(sessionId);
        if (session == null) {
            return createErrorResponse("Invalid emulator session");
        }
        
        return EmulatorService.setMemoryReadTracking(session, enable);
    }
    
    /**
     * Get memory reads
     */
    private Map<String, Object> getMemoryReads() {
        Program program = plugin.getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        // Get session for current program
        String sessionId = programEmulatorSessions.get(program);
        if (sessionId == null) {
            return createErrorResponse("Emulator not initialized for current program");
        }
        
        EmulatorService.EmulatorSession session = EmulatorService.getSession(sessionId);
        if (session == null) {
            return createErrorResponse("Invalid emulator session");
        }
        
        return EmulatorService.getMemoryReads(session);
    }
    
    /**
     * Set stack change tracking
     */
    private Map<String, Object> setStackChangeTracking(boolean enable) {
        Program program = plugin.getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        // Get session for current program
        String sessionId = programEmulatorSessions.get(program);
        if (sessionId == null) {
            return createErrorResponse("Emulator not initialized for current program");
        }
        
        EmulatorService.EmulatorSession session = EmulatorService.getSession(sessionId);
        if (session == null) {
            return createErrorResponse("Invalid emulator session");
        }
        
        return EmulatorService.setStackChangeTracking(session, enable);
    }
    
    /**
     * Get stack trace
     */
    private Map<String, Object> getStackTrace() {
        Program program = plugin.getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        // Get session for current program
        String sessionId = programEmulatorSessions.get(program);
        if (sessionId == null) {
            return createErrorResponse("Emulator not initialized for current program");
        }
        
        EmulatorService.EmulatorSession session = EmulatorService.getSession(sessionId);
        if (session == null) {
            return createErrorResponse("Invalid emulator session");
        }
        
        return EmulatorService.getStackTrace(session);
    }
}
