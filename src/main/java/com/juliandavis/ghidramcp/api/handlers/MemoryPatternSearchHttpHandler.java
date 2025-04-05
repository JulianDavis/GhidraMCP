package com.juliandavis.ghidramcp.api.handlers;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.services.MemoryPatternSearchService;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.util.Map;

/**
 * HTTP handler for memory pattern search operations.
 * Exposes endpoints for searching memory for specific byte patterns.
 */
public class MemoryPatternSearchHttpHandler extends BaseHttpHandler {

    private final MemoryPatternSearchService memoryPatternSearchService;

    /**
     * Constructor for the MemoryPatternSearchHttpHandler.
     *
     * @param plugin The GhidraMCPPlugin instance
     */
    public MemoryPatternSearchHttpHandler(GhidraMCPPlugin plugin) {
        super(plugin);
        this.memoryPatternSearchService = getOrCreateMemoryPatternSearchService();
    }

    @Override
    public void registerEndpoints() {
        // Register endpoint for memory pattern search
        getServer().createContext("/api/memory/pattern", exchange -> {
            Program currentProgram = getCurrentProgram();
            if (currentProgram == null) {
                sendJsonResponse(exchange, createErrorResponse("No program is currently open"));
                return;
            }

            // Handle different HTTP methods
            String method = exchange.getRequestMethod();
            if (isGetRequest(exchange)) {
                Map<String, String> queryParams = parseQueryParams(exchange);
                String pattern = queryParams.get("pattern");
                
                if (pattern == null || pattern.isEmpty()) {
                    sendJsonResponse(exchange, createErrorResponse("Pattern parameter is required"));
                    return;
                }

                // Parse optional parameters
                boolean searchExecutable = parseBoolean(queryParams.get("searchExecutable"), true);
                boolean searchOnlyReadable = parseBoolean(queryParams.get("searchOnlyReadable"), true);
                boolean caseSensitive = parseBoolean(queryParams.get("caseSensitive"), true);
                int maxResults = parseInt(queryParams.get("maxResults"), 100);

                // Search for pattern
                Map<String, Object> result = memoryPatternSearchService.searchForPattern(
                        currentProgram,
                        pattern,
                        searchExecutable,
                        searchOnlyReadable,
                        caseSensitive,
                        maxResults,
                        TaskMonitor.DUMMY
                );

                // Just pass through the standardized response from the service
                sendJsonResponse(exchange, result);
            } else if (isPostRequest(exchange)) {
                Map<String, String> params = parsePostParams(exchange);
                String pattern = params.get("pattern");
                
                if (pattern == null || pattern.isEmpty()) {
                    sendJsonResponse(exchange, createErrorResponse("Pattern parameter is required"));
                    return;
                }

                // Parse optional parameters
                boolean searchExecutable = parseBoolean(params.get("searchExecutable"), true);
                boolean searchOnlyReadable = parseBoolean(params.get("searchOnlyReadable"), true);
                boolean caseSensitive = parseBoolean(params.get("caseSensitive"), true);
                int maxResults = parseInt(params.get("maxResults"), 100);

                // Search for pattern
                Map<String, Object> result = memoryPatternSearchService.searchForPattern(
                        currentProgram,
                        pattern,
                        searchExecutable,
                        searchOnlyReadable,
                        caseSensitive,
                        maxResults,
                        TaskMonitor.DUMMY
                );

                // Just pass through the standardized response from the service
                sendJsonResponse(exchange, result);
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
     * Get or create the MemoryPatternSearchService instance
     * 
     * @return The MemoryPatternSearchService instance
     */
    private MemoryPatternSearchService getOrCreateMemoryPatternSearchService() {
        MemoryPatternSearchService service = getService(MemoryPatternSearchService.SERVICE_NAME, MemoryPatternSearchService.class);
        if (service == null) {
            service = new MemoryPatternSearchService();
            // Register the service with the service registry
            plugin.getServiceRegistry().registerService(service);
        }
        return service;
    }
}