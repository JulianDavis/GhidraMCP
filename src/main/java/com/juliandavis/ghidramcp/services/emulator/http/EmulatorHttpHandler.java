package com.juliandavis.ghidramcp.services.emulator.http;

import com.juliandavis.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.api.handlers.BaseHttpHandler;
import com.juliandavis.ghidramcp.services.ServiceRegistry;
import com.juliandavis.ghidramcp.services.emulator.EmulatorService;
import com.juliandavis.ghidramcp.services.emulator.operations.EmulatorOperations;
import com.juliandavis.ghidramcp.services.emulator.session.EmulatorSession;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.util.HashMap;
import java.util.Map;

/**
 * HTTP handler for emulator-related endpoints in the GhidraMCPPlugin.
 * Provides endpoints for initializing, controlling, and retrieving state from the emulator.
 */
public class EmulatorHttpHandler extends BaseHttpHandler {

    // Track the current emulator session for each program
    private final Map<Program, String> programEmulatorSessions = new HashMap<>();
    private final EmulatorService emulatorService;
    
    /**
     * Create a new EmulatorHttpHandler
     * 
     * @param plugin The GhidraMCPPlugin instance
     */
    public EmulatorHttpHandler(GhidraMCPPlugin plugin) {
        super(plugin);
        this.emulatorService = getOrCreateEmulatorService();
    }
    
    /**
     * Register all endpoints with the HTTP server
     */
    @Override
    public void registerEndpoints() {
        // Initialize emulator session
        getPlugin().getServer().createContext("/emulator/initialize", exchange -> {
            Map<String, String> params = getPlugin().parsePostParams(exchange);
            String addressStr = params.get("address");
            boolean writeTracking = Boolean.parseBoolean(params.getOrDefault("writeTracking", "true"));
            
            Map<String, Object> response = initializeEmulator(addressStr, writeTracking);
            getPlugin().sendJsonResponse(exchange, response);
        });
        
        // Step emulator
        getPlugin().getServer().createContext("/emulator/step", exchange -> {
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response = session != null ? 
                EmulatorOperations.stepEmulator(session) : 
                createErrorResponse("No valid emulator session for current program");
            getPlugin().sendJsonResponse(exchange, response);
        });
        
        // Run emulator
        getPlugin().getServer().createContext("/emulator/run", exchange -> {
            Map<String, String> params = getPlugin().parsePostParams(exchange);
            int maxSteps = Integer.parseInt(params.getOrDefault("maxSteps", "1000"));
            boolean stopOnBreakpoint = Boolean.parseBoolean(params.getOrDefault("stopOnBreakpoint", "true"));
            String stopAddress = params.get("stopAddress");
            
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response = session != null ? 
                EmulatorOperations.runEmulator(session, maxSteps, stopOnBreakpoint, stopAddress) : 
                createErrorResponse("No valid emulator session for current program");
            getPlugin().sendJsonResponse(exchange, response);
        });
        
        // Get emulator state
        getPlugin().getServer().createContext("/emulator/getState", exchange -> {
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response = session != null ? 
                EmulatorOperations.getEmulatorState(session) : 
                createErrorResponse("No valid emulator session for current program");
            getPlugin().sendJsonResponse(exchange, response);
        });
        
        // Get memory writes
        getPlugin().getServer().createContext("/emulator/getWrites", exchange -> {
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response = session != null ? 
                EmulatorOperations.getMemoryWrites(session) : 
                createErrorResponse("No valid emulator session for current program");
            getPlugin().sendJsonResponse(exchange, response);
        });
        
        // Import memory
        getPlugin().getServer().createContext("/emulator/importMemory", exchange -> {
            Map<String, String> params = getPlugin().parsePostParams(exchange);
            String fromAddress = params.get("fromAddress");
            String length = params.get("length");
            
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response = session != null ? 
                EmulatorOperations.importMemoryToProgram(session, fromAddress, length) : 
                createErrorResponse("No valid emulator session for current program");
            getPlugin().sendJsonResponse(exchange, response);
        });
        
        // Set breakpoint
        getPlugin().getServer().createContext("/emulator/setBreakpoint", exchange -> {
            String addressStr = new String(exchange.getRequestBody().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response = session != null ? 
                EmulatorOperations.setBreakpoint(session, addressStr) : 
                createErrorResponse("No valid emulator session for current program");
            getPlugin().sendJsonResponse(exchange, response);
        });
        
        // Clear breakpoint
        getPlugin().getServer().createContext("/emulator/clearBreakpoint", exchange -> {
            String addressStr = new String(exchange.getRequestBody().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response = session != null ? 
                EmulatorOperations.clearBreakpoint(session, addressStr) : 
                createErrorResponse("No valid emulator session for current program");
            getPlugin().sendJsonResponse(exchange, response);
        });
        
        // Get breakpoints
        getPlugin().getServer().createContext("/emulator/getBreakpoints", exchange -> {
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response = session != null ? 
                EmulatorOperations.getBreakpoints(session) : 
                createErrorResponse("No valid emulator session for current program");
            getPlugin().sendJsonResponse(exchange, response);
        });
        
        // Reset emulator
        getPlugin().getServer().createContext("/emulator/reset", exchange -> {
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response = session != null ? 
                EmulatorOperations.resetEmulator(session) : 
                createErrorResponse("No valid emulator session for current program");
            getPlugin().sendJsonResponse(exchange, response);
        });
        
        // Set conditional breakpoint
        getPlugin().getServer().createContext("/emulator/setConditionalBreakpoint", exchange -> {
            Map<String, String> params = getPlugin().parsePostParams(exchange);
            String addressStr = params.get("address");
            String condition = params.get("condition");
            
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response = session != null ? 
                EmulatorOperations.setConditionalBreakpoint(session, addressStr, condition) : 
                createErrorResponse("No valid emulator session for current program");
            getPlugin().sendJsonResponse(exchange, response);
        });
        
        // Get conditional breakpoints
        getPlugin().getServer().createContext("/emulator/getConditionalBreakpoints", exchange -> {
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response = session != null ? 
                EmulatorOperations.getConditionalBreakpoints(session) : 
                createErrorResponse("No valid emulator session for current program");
            getPlugin().sendJsonResponse(exchange, response);
        });
        
        // Set register value
        getPlugin().getServer().createContext("/emulator/setRegister", exchange -> {
            Map<String, String> params = getPlugin().parsePostParams(exchange);
            String register = params.get("register");
            String value = params.get("value");
            
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response = session != null ? 
                EmulatorOperations.setRegisterValue(session, register, value) : 
                createErrorResponse("No valid emulator session for current program");
            getPlugin().sendJsonResponse(exchange, response);
        });
        
        // Get register value
        getPlugin().getServer().createContext("/emulator/getRegister", exchange -> {
            Map<String, String> params = getPlugin().parseQueryParams(exchange);
            String register = params.get("register");
            
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response = session != null ? 
                EmulatorOperations.getRegisterValue(session, register) : 
                createErrorResponse("No valid emulator session for current program");
            getPlugin().sendJsonResponse(exchange, response);
        });
        
        // Get all registers
        getPlugin().getServer().createContext("/emulator/getRegisters", exchange -> {
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response = session != null ? 
                EmulatorOperations.getRegisterNames(session) : 
                createErrorResponse("No valid emulator session for current program");
            getPlugin().sendJsonResponse(exchange, response);
        });
        
        // Write memory
        getPlugin().getServer().createContext("/emulator/writeMemory", exchange -> {
            Map<String, String> params = getPlugin().parsePostParams(exchange);
            String address = params.get("address");
            String bytesHex = params.get("bytes");
            
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response = session != null ? 
                EmulatorOperations.writeMemory(session, address, bytesHex) : 
                createErrorResponse("No valid emulator session for current program");
            getPlugin().sendJsonResponse(exchange, response);
        });
        
        // Read memory
        getPlugin().getServer().createContext("/emulator/readMemory", exchange -> {
            Map<String, String> params = getPlugin().parseQueryParams(exchange);
            String address = params.get("address");
            int length = Integer.parseInt(params.getOrDefault("length", "16"));
            
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response = session != null ? 
                EmulatorOperations.readMemory(session, address, length) : 
                createErrorResponse("No valid emulator session for current program");
            getPlugin().sendJsonResponse(exchange, response);
        });
        
        // Set memory read tracking
        getPlugin().getServer().createContext("/emulator/setMemoryReadTracking", exchange -> {
            Map<String, String> params = getPlugin().parsePostParams(exchange);
            boolean enable = Boolean.parseBoolean(params.getOrDefault("enable", "true"));
            
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response = session != null ? 
                EmulatorOperations.setMemoryReadTracking(session, enable) : 
                createErrorResponse("No valid emulator session for current program");
            getPlugin().sendJsonResponse(exchange, response);
        });
        
        // Get memory reads
        getPlugin().getServer().createContext("/emulator/getReads", exchange -> {
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response = session != null ? 
                EmulatorOperations.getMemoryReads(session) : 
                createErrorResponse("No valid emulator session for current program");
            getPlugin().sendJsonResponse(exchange, response);
        });
        
        // Set stack change tracking
        getPlugin().getServer().createContext("/emulator/setStackChangeTracking", exchange -> {
            Map<String, String> params = getPlugin().parsePostParams(exchange);
            boolean enable = Boolean.parseBoolean(params.getOrDefault("enable", "true"));
            
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response = session != null ? 
                EmulatorOperations.setStackChangeTracking(session, enable) : 
                createErrorResponse("No valid emulator session for current program");
            getPlugin().sendJsonResponse(exchange, response);
        });
        
        // Get stack trace
        getPlugin().getServer().createContext("/emulator/getStackTrace", exchange -> {
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response = session != null ? 
                EmulatorOperations.getStackTrace(session) : 
                createErrorResponse("No valid emulator session for current program");
            getPlugin().sendJsonResponse(exchange, response);
        });
        
        // Get register changes
        getPlugin().getServer().createContext("/emulator/getRegisterChanges", exchange -> {
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response = session != null ? 
                EmulatorOperations.getRegisterChanges(session) : 
                createErrorResponse("No valid emulator session for current program");
            getPlugin().sendJsonResponse(exchange, response);
        });
        
        // Get stdout content
        getPlugin().getServer().createContext("/emulator/getStdout", exchange -> {
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response = session != null ? 
                EmulatorOperations.getStdoutContent(session) : 
                createErrorResponse("No valid emulator session for current program");
            getPlugin().sendJsonResponse(exchange, response);
        });
        
        // Get stderr content
        getPlugin().getServer().createContext("/emulator/getStderr", exchange -> {
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response = session != null ? 
                EmulatorOperations.getStderrContent(session) : 
                createErrorResponse("No valid emulator session for current program");
            getPlugin().sendJsonResponse(exchange, response);
        });
        
        // Provide stdin data
        getPlugin().getServer().createContext("/emulator/provideStdin", exchange -> {
            Map<String, String> params = getPlugin().parsePostParams(exchange);
            String data = params.get("data");
            
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response = session != null ? 
                EmulatorOperations.provideStdinData(session, data) : 
                createErrorResponse("No valid emulator session for current program");
            getPlugin().sendJsonResponse(exchange, response);
        });
        
        // Dispose emulator session
        getPlugin().getServer().createContext("/emulator/dispose", exchange -> {
            Map<String, Object> response = disposeEmulatorSession();
            getPlugin().sendJsonResponse(exchange, response);
        });
    }
    
    /**
     * Get or create the EmulatorService instance
     * 
     * @return The EmulatorService instance
     */
    private EmulatorService getOrCreateEmulatorService() {
        EmulatorService service = (EmulatorService) ServiceRegistry.getInstance().getService(EmulatorService.SERVICE_NAME);
        if (service == null) {
            service = new EmulatorService();
            ServiceRegistry.getInstance().registerService(service);
        }
        return service;
    }
    
    /**
     * Helper method to retrieve and validate the emulator session for the current program.
     * 
     * @return The validated EmulatorSession or null if validation fails
     */
    private EmulatorSession getValidatedSession() {
        // Get the current program
        Program program = getPlugin().getCurrentProgram();
        if (program == null) {
            return null;
        }
        
        // Get session for current program
        String sessionId = programEmulatorSessions.get(program);
        if (sessionId == null) {
            return null;
        }
        
        // Get and validate the session
        return emulatorService.getSession(sessionId);
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
        Program program = getPlugin().getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        Map<String, Object> response = new HashMap<>();
        
        try {
            // Check if there's already a session for this program
            String existingSessionId = programEmulatorSessions.get(program);
            EmulatorSession session;
            
            if (existingSessionId != null) {
                session = emulatorService.getSession(existingSessionId);
                
                // If a session exists but is invalid, properly dispose it before creating a new one
                emulatorService.disposeSession(existingSessionId);
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
            session = emulatorService.createSession(program);
            programEmulatorSessions.put(program, session.getId());
            
            // Initialize emulator with tracking options
            boolean success = emulatorService.initializeEmulator(session, addressStr, writeTracking);
            
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
     * Dispose of the current emulator session
     */
    private Map<String, Object> disposeEmulatorSession() {
        Program program = getPlugin().getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        String sessionId = programEmulatorSessions.get(program);
        if (sessionId == null) {
            return createErrorResponse("No emulator session for current program");
        }
        
        boolean disposed = emulatorService.disposeSession(sessionId);
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
}
