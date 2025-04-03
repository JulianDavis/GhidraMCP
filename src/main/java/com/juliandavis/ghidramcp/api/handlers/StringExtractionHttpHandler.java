package com.juliandavis.ghidramcp.api.handlers;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.analysis.search.StringExtractionService;
import com.sun.net.httpserver.HttpExchange;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * HTTP handler for string extraction operations.
 * Exposes endpoints for finding strings in memory.
 */
public class StringExtractionHttpHandler extends BaseHttpHandler {

    private final StringExtractionService stringExtractionService;

    /**
     * Constructor for the StringExtractionHttpHandler.
     *
     * @param plugin The GhidraMCPPlugin instance
     */
    public StringExtractionHttpHandler(GhidraMCPPlugin plugin) {
        super(plugin);
        this.stringExtractionService = getOrCreateStringExtractionService();
    }

    @Override
    public void registerEndpoints() {
        // Register endpoint for string extraction
        plugin.getServer().createContext("/api/strings", exchange -> {
            Program currentProgram = getCurrentProgram();
            if (currentProgram == null) {
                sendJsonResponse(exchange, createErrorResponse("No program is currently open"));
                return;
            }

            // Handle different HTTP methods
            String method = exchange.getRequestMethod();
            if ("GET".equalsIgnoreCase(method)) {
                Map<String, String> queryParams = plugin.parseQueryParams(exchange);
                
                // Parse parameters
                int minLength = parseInt(queryParams.get("minLength"), 4);
                String encodingStr = queryParams.get("encoding");
                StringExtractionService.StringEncoding encoding = parseEncoding(encodingStr);
                boolean searchRWMemory = parseBoolean(queryParams.get("searchRWMemory"), true);
                boolean searchROMemory = parseBoolean(queryParams.get("searchROMemory"), true);
                boolean searchExecutableMemory = parseBoolean(queryParams.get("searchExecutableMemory"), false);
                int maxResults = parseInt(queryParams.get("maxResults"), 1000);

                // Extract strings
                List<Map<String, Object>> results = stringExtractionService.extractStrings(
                        currentProgram,
                        minLength,
                        encoding,
                        searchRWMemory,
                        searchROMemory,
                        searchExecutableMemory,
                        maxResults,
                        TaskMonitor.DUMMY
                );

                Map<String, Object> response = new HashMap<>();
                response.put("strings", results);
                response.put("count", results.size());
                response.put("searchCriteria", Map.of(
                        "minLength", minLength,
                        "encoding", encoding.toString(),
                        "searchRWMemory", searchRWMemory,
                        "searchROMemory", searchROMemory,
                        "searchExecutableMemory", searchExecutableMemory,
                        "maxResults", maxResults
                ));

                sendJsonResponse(exchange, response);
            } else if ("POST".equalsIgnoreCase(method)) {
                Map<String, String> params = plugin.parsePostParams(exchange);
                
                // Parse parameters
                int minLength = parseInt(params.get("minLength"), 4);
                String encodingStr = params.get("encoding");
                StringExtractionService.StringEncoding encoding = parseEncoding(encodingStr);
                boolean searchRWMemory = parseBoolean(params.get("searchRWMemory"), true);
                boolean searchROMemory = parseBoolean(params.get("searchROMemory"), true);
                boolean searchExecutableMemory = parseBoolean(params.get("searchExecutableMemory"), false);
                int maxResults = parseInt(params.get("maxResults"), 1000);

                // Extract strings
                List<Map<String, Object>> results = stringExtractionService.extractStrings(
                        currentProgram,
                        minLength,
                        encoding,
                        searchRWMemory,
                        searchROMemory,
                        searchExecutableMemory,
                        maxResults,
                        TaskMonitor.DUMMY
                );

                Map<String, Object> response = new HashMap<>();
                response.put("strings", results);
                response.put("count", results.size());
                response.put("searchCriteria", Map.of(
                        "minLength", minLength,
                        "encoding", encoding.toString(),
                        "searchRWMemory", searchRWMemory,
                        "searchROMemory", searchROMemory,
                        "searchExecutableMemory", searchExecutableMemory,
                        "maxResults", maxResults
                ));

                sendJsonResponse(exchange, response);
            } else {
                sendJsonResponse(exchange, createErrorResponse("Unsupported HTTP method: " + method));
            }
        });
    }

    /**
     * Parse a string encoding parameter
     */
    private StringExtractionService.StringEncoding parseEncoding(String encoding) {
        if (encoding == null) {
            return StringExtractionService.StringEncoding.ALL;
        }
        
        try {
            return StringExtractionService.StringEncoding.valueOf(encoding.toUpperCase());
        } catch (IllegalArgumentException e) {
            return StringExtractionService.StringEncoding.ALL;
        }
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
     * Get or create the StringExtractionService instance
     * 
     * @return The StringExtractionService instance
     */
    private StringExtractionService getOrCreateStringExtractionService() {
        StringExtractionService service = getService(StringExtractionService.SERVICE_NAME, StringExtractionService.class);
        if (service == null) {
            service = new StringExtractionService();
            // Register the service with the service registry
            plugin.getServiceRegistry().registerService(service);
        }
        return service;
    }
}