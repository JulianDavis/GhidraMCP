package com.juliandavis.ghidramcp.services.emulator;

import com.juliandavis.GhidraMCPPlugin;
import com.juliandavis.ArchitectureHelper;
import com.juliandavis.ghidramcp.emulation.syscall.SyscallMappings;
import com.juliandavis.ghidramcp.http.BaseHttpHandler;
import com.juliandavis.ghidramcp.services.ServiceRegistry;
import com.juliandavis.ghidramcp.services.emulator.session.EmulatorSession;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.program.model.address.Address;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.lang.Register;
import ghidra.util.task.TaskMonitor;

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
            Map<String, Object> response = stepEmulator();
            getPlugin().sendJsonResponse(exchange, response);
        });
        
        // Run emulator
        getPlugin().getServer().createContext("/emulator/run", exchange -> {
            Map<String, String> params = getPlugin().parsePostParams(exchange);
            int maxSteps = Integer.parseInt(params.getOrDefault("maxSteps", "1000"));
            boolean stopOnBreakpoint = Boolean.parseBoolean(params.getOrDefault("stopOnBreakpoint", "true"));
            String stopAddress = params.get("stopAddress");
            
            Map<String, Object> response = runEmulator(maxSteps, stopOnBreakpoint, stopAddress);
            getPlugin().sendJsonResponse(exchange, response);
        });
        
        // Get emulator state
        getPlugin().getServer().createContext("/emulator/getState", exchange -> {
            Map<String, Object> response = getEmulatorState();
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
     * Step the emulator forward by one instruction
     */
    private Map<String, Object> stepEmulator() {
        EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        return EmulatorOperations.stepEmulator(session);
    }
    
    /**
     * Run the emulator until a condition is met
     */
    private Map<String, Object> runEmulator(int maxSteps, boolean stopOnBreakpoint, String stopAddress) {
        EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        return EmulatorOperations.runEmulator(session, maxSteps, stopOnBreakpoint, stopAddress);
    }
    
    /**
     * Get the current emulator state
     */
    private Map<String, Object> getEmulatorState() {
        EmulatorSession session = getValidatedSession();
        if (session == null) {
            return createErrorResponse("No valid emulator session for current program");
        }
        
        return EmulatorOperations.getEmulatorState(session);
    }
}
