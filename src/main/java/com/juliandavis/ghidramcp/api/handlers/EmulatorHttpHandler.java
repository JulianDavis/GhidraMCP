package com.juliandavis.ghidramcp.api.handlers;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.emulation.core.EmulatorService;
import com.juliandavis.ghidramcp.emulation.core.EmulatorSession;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.util.HashMap;
import java.util.Map;

/**
 * HTTP handler for emulator-related endpoints in the GhidraMCP plugin.
 * Provides endpoints for initializing, controlling, and retrieving state from the emulator.
 */
public class EmulatorHttpHandler extends BaseHttpHandler {

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
        plugin.getServer().createContext("/emulator/initialize", exchange -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            String addressStr = params.get("address");
            boolean writeTracking = Boolean.parseBoolean(params.getOrDefault("writeTracking", "true"));
            
            Map<String, Object> response = initializeEmulator(addressStr, writeTracking);
            sendJsonResponse(exchange, response);
        });
        
        // Step emulator
        plugin.getServer().createContext("/emulator/step", exchange -> {
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response;
            
            if (session == null) {
                response = createErrorResponse("No valid emulator session for current program");
            } else {
                response = emulatorService.step(session.getId());
            }
            
            sendJsonResponse(exchange, response);
        });
        
        // Run emulator
        plugin.getServer().createContext("/emulator/run", exchange -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            int maxSteps = Integer.parseInt(params.getOrDefault("maxSteps", "1000"));
            boolean stopOnBreakpoint = Boolean.parseBoolean(params.getOrDefault("stopOnBreakpoint", "true"));
            String stopAddress = params.get("stopAddress");
            
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response;
            
            if (session == null) {
                response = createErrorResponse("No valid emulator session for current program");
            } else {
                response = emulatorService.run(session.getId(), maxSteps, stopOnBreakpoint, stopAddress);
            }
            
            sendJsonResponse(exchange, response);
        });
        
        // Get emulator state
        plugin.getServer().createContext("/emulator/getState", exchange -> {
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response;
            
            if (session == null) {
                response = createErrorResponse("No valid emulator session for current program");
            } else {
                response = emulatorService.getState(session.getId());
            }
            
            sendJsonResponse(exchange, response);
        });
        
        // Get memory writes
        plugin.getServer().createContext("/emulator/getWrites", exchange -> {
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response;
            
            if (session == null) {
                response = createErrorResponse("No valid emulator session for current program");
            } else {
                response = emulatorService.getWrites(session.getId());
            }
            
            sendJsonResponse(exchange, response);
        });
        
        // Reset emulator
        plugin.getServer().createContext("/emulator/reset", exchange -> {
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response;
            
            if (session == null) {
                response = createErrorResponse("No valid emulator session for current program");
            } else {
                response = emulatorService.reset(session.getId());
            }
            
            sendJsonResponse(exchange, response);
        });
        
        // Set breakpoint
        plugin.getServer().createContext("/emulator/setBreakpoint", exchange -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            String address = params.get("address");
            
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response;
            
            if (session == null) {
                response = createErrorResponse("No valid emulator session for current program");
            } else {
                response = emulatorService.setBreakpoint(session.getId(), address);
            }
            
            sendJsonResponse(exchange, response);
        });
        
        // Clear breakpoint
        plugin.getServer().createContext("/emulator/clearBreakpoint", exchange -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            String address = params.get("address");
            
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response;
            
            if (session == null) {
                response = createErrorResponse("No valid emulator session for current program");
            } else {
                response = emulatorService.clearBreakpoint(session.getId(), address);
            }
            
            sendJsonResponse(exchange, response);
        });
        
        // Get breakpoints
        plugin.getServer().createContext("/emulator/getBreakpoints", exchange -> {
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response;
            
            if (session == null) {
                response = createErrorResponse("No valid emulator session for current program");
            } else {
                response = emulatorService.getBreakpoints(session.getId());
            }
            
            sendJsonResponse(exchange, response);
        });
        
        // Set conditional breakpoint
        plugin.getServer().createContext("/emulator/setConditionalBreakpoint", exchange -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            String address = params.get("address");
            String condition = params.get("condition");
            
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response;
            
            if (session == null) {
                response = createErrorResponse("No valid emulator session for current program");
            } else {
                response = emulatorService.setConditionalBreakpoint(session.getId(), address, condition);
            }
            
            sendJsonResponse(exchange, response);
        });
        
        // Get conditional breakpoints
        plugin.getServer().createContext("/emulator/getConditionalBreakpoints", exchange -> {
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response;
            
            if (session == null) {
                response = createErrorResponse("No valid emulator session for current program");
            } else {
                response = emulatorService.getConditionalBreakpoints(session.getId());
            }
            
            sendJsonResponse(exchange, response);
        });
        
        // Set register value
        plugin.getServer().createContext("/emulator/setRegister", exchange -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            String register = params.get("register");
            String value = params.get("value");
            
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response;
            
            if (session == null) {
                response = createErrorResponse("No valid emulator session for current program");
            } else {
                response = emulatorService.setRegisterValue(session.getId(), register, value);
            }
            
            sendJsonResponse(exchange, response);
        });
        
        // Get register value
        plugin.getServer().createContext("/emulator/getRegister", exchange -> {
            Map<String, String> params = plugin.parseQueryParams(exchange);
            String register = params.get("register");
            
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response;
            
            if (session == null) {
                response = createErrorResponse("No valid emulator session for current program");
            } else {
                response = emulatorService.getRegisterValue(session.getId(), register);
            }
            
            sendJsonResponse(exchange, response);
        });
        
        // Get all registers
        plugin.getServer().createContext("/emulator/getRegisters", exchange -> {
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response;
            
            if (session == null) {
                response = createErrorResponse("No valid emulator session for current program");
            } else {
                response = emulatorService.getRegisters(session.getId());
            }
            
            sendJsonResponse(exchange, response);
        });
        
        // Write memory
        plugin.getServer().createContext("/emulator/writeMemory", exchange -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            String address = params.get("address");
            String bytesHex = params.get("bytes_hex");
            
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response;
            
            if (session == null) {
                response = createErrorResponse("No valid emulator session for current program");
            } else {
                response = emulatorService.writeMemory(session.getId(), address, bytesHex);
            }
            
            sendJsonResponse(exchange, response);
        });
        
        // Read memory
        plugin.getServer().createContext("/emulator/readMemory", exchange -> {
            Map<String, String> params = plugin.parseQueryParams(exchange);
            String address = params.get("address");
            int length = Integer.parseInt(params.getOrDefault("length", "16"));
            
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response;
            
            if (session == null) {
                response = createErrorResponse("No valid emulator session for current program");
            } else {
                response = emulatorService.readMemory(session.getId(), address, length);
            }
            
            sendJsonResponse(exchange, response);
        });
        
        // Set memory read tracking
        plugin.getServer().createContext("/emulator/setMemoryReadTracking", exchange -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            boolean enable = Boolean.parseBoolean(params.getOrDefault("enable", "true"));
            
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response;
            
            if (session == null) {
                response = createErrorResponse("No valid emulator session for current program");
            } else {
                response = emulatorService.setMemoryReadTracking(session.getId(), enable);
            }
            
            sendJsonResponse(exchange, response);
        });
        
        // Get memory reads
        plugin.getServer().createContext("/emulator/getReads", exchange -> {
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response;
            
            if (session == null) {
                response = createErrorResponse("No valid emulator session for current program");
            } else {
                response = emulatorService.getReads(session.getId());
            }
            
            sendJsonResponse(exchange, response);
        });
        
        // Set stack change tracking
        plugin.getServer().createContext("/emulator/setStackChangeTracking", exchange -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            boolean enable = Boolean.parseBoolean(params.getOrDefault("enable", "true"));
            
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response;
            
            if (session == null) {
                response = createErrorResponse("No valid emulator session for current program");
            } else {
                response = emulatorService.setStackChangeTracking(session.getId(), enable);
            }
            
            sendJsonResponse(exchange, response);
        });
        
        // Get stack trace
        plugin.getServer().createContext("/emulator/getStackTrace", exchange -> {
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response;
            
            if (session == null) {
                response = createErrorResponse("No valid emulator session for current program");
            } else {
                response = emulatorService.getStackTrace(session.getId());
            }
            
            sendJsonResponse(exchange, response);
        });
        
        // Import memory
        plugin.getServer().createContext("/emulator/importMemory", exchange -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            String fromAddress = params.get("from_address");
            String length = params.get("length");
            
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response;
            
            if (session == null) {
                response = createErrorResponse("No valid emulator session for current program");
            } else {
                response = emulatorService.importMemory(session.getId(), fromAddress, length);
            }
            
            sendJsonResponse(exchange, response);
        });
        
        // Get register changes
        plugin.getServer().createContext("/emulator/getRegisterChanges", exchange -> {
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response;
            
            if (session == null) {
                response = createErrorResponse("No valid emulator session for current program");
            } else {
                response = emulatorService.getRegisterChanges(session.getId());
            }
            
            sendJsonResponse(exchange, response);
        });
        
        // Get stdout content
        plugin.getServer().createContext("/emulator/getStdout", exchange -> {
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response;
            
            if (session == null) {
                response = createErrorResponse("No valid emulator session for current program");
            } else {
                response = emulatorService.getStdoutContent(session.getId());
            }
            
            sendJsonResponse(exchange, response);
        });
        
        // Get stderr content
        plugin.getServer().createContext("/emulator/getStderr", exchange -> {
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response;
            
            if (session == null) {
                response = createErrorResponse("No valid emulator session for current program");
            } else {
                response = emulatorService.getStderrContent(session.getId());
            }
            
            sendJsonResponse(exchange, response);
        });
        
        // Provide stdin data
        plugin.getServer().createContext("/emulator/provideStdin", exchange -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            String data = params.get("data");
            
            EmulatorSession session = getValidatedSession();
            Map<String, Object> response;
            
            if (session == null) {
                response = createErrorResponse("No valid emulator session for current program");
            } else {
                response = emulatorService.provideStdinData(session.getId(), data);
            }
            
            sendJsonResponse(exchange, response);
        });
    }
    
    /**
     * Initialize the emulator at the specified address
     * 
     * @param addressStr The address to initialize at
     * @param writeTracking Whether to enable write tracking
     * @return A Map containing the result of the operation
     */
    private Map<String, Object> initializeEmulator(String addressStr, boolean writeTracking) {
        Program program = getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        // Check if there's already a session for this program
        String existingSessionId = programEmulatorSessions.get(program);
        if (existingSessionId != null) {
            // Remove the existing session from the registry
            programEmulatorSessions.remove(program);
        }
        
        // Initialize a new emulator
        Map<String, Object> result = emulatorService.initialize(addressStr, writeTracking);
        
        // Check if initialization succeeded
        if (!result.containsKey("error") && result.containsKey("sessionId")) {
            // Store the session ID for the current program
            programEmulatorSessions.put(program, (String) result.get("sessionId"));
            Msg.info(this, "Initialized emulator for program: " + program.getName() + 
                    " with session: " + result.get("sessionId"));
        }
        
        return result;
    }
    
    /**
     * Get or create the EmulatorService instance
     * 
     * @return The EmulatorService instance
     */
    private EmulatorService getOrCreateEmulatorService() {
        EmulatorService service = getService(EmulatorService.SERVICE_NAME, EmulatorService.class);
        if (service == null) {
            service = new EmulatorService();
            // Register the service with the service registry
            plugin.getServiceRegistry().registerService(service);
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
        Program program = getCurrentProgram();
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
}