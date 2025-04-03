package com.juliandavis.ghidramcp.api.handlers;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.analysis.memory.MemoryCrossReferenceService;
import com.sun.net.httpserver.HttpExchange;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.util.Map;

/**
 * HTTP handler for memory cross-reference operations.
 * Exposes endpoints for finding references to addresses in memory.
 */
public class MemoryCrossReferenceHttpHandler extends BaseHttpHandler {

    private final MemoryCrossReferenceService memoryCrossReferenceService;

    /**
     * Constructor for the MemoryCrossReferenceHttpHandler.
     *
     * @param plugin The GhidraMCPPlugin instance
     */
    public MemoryCrossReferenceHttpHandler(GhidraMCPPlugin plugin) {
        super(plugin);
        this.memoryCrossReferenceService = getOrCreateMemoryCrossReferenceService();
    }

    @Override
    public void registerEndpoints() {
        // Register endpoint for finding all references
        plugin.getServer().createContext("/api/memory/references", exchange -> {
            Program currentProgram = getCurrentProgram();
            if (currentProgram == null) {
                sendJsonResponse(exchange, createErrorResponse("No program is currently open"));
                return;
            }

            // Handle different HTTP methods
            String method = exchange.getRequestMethod();
            if ("GET".equalsIgnoreCase(method)) {
                Map<String, String> queryParams = plugin.parseQueryParams(exchange);
                String targetAddress = queryParams.get("address");
                
                if (targetAddress == null || targetAddress.isEmpty()) {
                    sendJsonResponse(exchange, createErrorResponse("Address parameter is required"));
                    return;
                }

                // Parse optional parameters
                boolean includeMemoryScan = parseBoolean(queryParams.get("includeMemoryScan"), false);
                boolean searchOnlyExecutable = parseBoolean(queryParams.get("searchOnlyExecutable"), true);
                boolean searchOnlyReadable = parseBoolean(queryParams.get("searchOnlyReadable"), true);
                int maxScanResults = parseInt(queryParams.get("maxScanResults"), 100);

                // Find references
                Map<String, Object> results = memoryCrossReferenceService.findAllReferences(
                        currentProgram,
                        targetAddress,
                        includeMemoryScan,
                        searchOnlyExecutable,
                        searchOnlyReadable,
                        maxScanResults,
                        TaskMonitor.DUMMY
                );

                sendJsonResponse(exchange, results);
            } else if ("POST".equalsIgnoreCase(method)) {
                Map<String, String> params = plugin.parsePostParams(exchange);
                String targetAddress = params.get("address");
                
                if (targetAddress == null || targetAddress.isEmpty()) {
                    sendJsonResponse(exchange, createErrorResponse("Address parameter is required"));
                    return;
                }

                // Parse optional parameters
                boolean includeMemoryScan = parseBoolean(params.get("includeMemoryScan"), false);
                boolean searchOnlyExecutable = parseBoolean(params.get("searchOnlyExecutable"), true);
                boolean searchOnlyReadable = parseBoolean(params.get("searchOnlyReadable"), true);
                int maxScanResults = parseInt(params.get("maxScanResults"), 100);

                // Find references
                Map<String, Object> results = memoryCrossReferenceService.findAllReferences(
                        currentProgram,
                        targetAddress,
                        includeMemoryScan,
                        searchOnlyExecutable,
                        searchOnlyReadable,
                        maxScanResults,
                        TaskMonitor.DUMMY
                );

                sendJsonResponse(exchange, results);
            } else {
                sendJsonResponse(exchange, createErrorResponse("Unsupported HTTP method: " + method));
            }
        });
    }

    /**
     * Parse a boolean parameter, with default value if missing or invalid
     */
    private boolean parseBoolean(String value, boolean defaultValue) {
        if (value == null) {
            return defaultValue;
        }
        return "true".equalsIgnoreCase(value) || "1".equals(value) || "yes".equalsIgnoreCase(value);
    }

    /**
     * Parse an integer parameter, with default value if missing or invalid
     */
    private int parseInt(String value, int defaultValue) {
        if (value == null) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }
    
    /**
     * Get or create the MemoryCrossReferenceService instance
     * 
     * @return The MemoryCrossReferenceService instance
     */
    private MemoryCrossReferenceService getOrCreateMemoryCrossReferenceService() {
        MemoryCrossReferenceService service = getService(MemoryCrossReferenceService.SERVICE_NAME, MemoryCrossReferenceService.class);
        if (service == null) {
            service = new MemoryCrossReferenceService();
            // Register the service with the service registry
            plugin.getServiceRegistry().registerService(service);
        }
        return service;
    }
}