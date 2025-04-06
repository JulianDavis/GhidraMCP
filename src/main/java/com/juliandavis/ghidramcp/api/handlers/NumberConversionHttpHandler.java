package com.juliandavis.ghidramcp.api.handlers;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.services.NumberConversionService;
import ghidra.util.Msg;

import java.io.IOException;
import java.util.Map;

/**
 * HTTP handler for number conversion endpoints in the GhidraMCP plugin.
 * Provides endpoints for converting numbers between different representations.
 */
public class NumberConversionHttpHandler extends BaseHttpHandler {

    private final NumberConversionService numberConversionService;

    /**
     * Creates a new NumberConversionHttpHandler.
     *
     * @param plugin The GhidraMCPPlugin instance
     */
    public NumberConversionHttpHandler(GhidraMCPPlugin plugin) {
        super(plugin);
        this.numberConversionService = getOrCreateNumberConversionService();
    }

    /**
     * Register all endpoints with the HTTP server
     */
    @Override
    public void registerEndpoints() {
        // Convert number
        getServer().createContext("/number/convert", exchange -> {
            try {
                // Check if this is a GET or POST request
                if (isGetRequest(exchange)) {
                    // Handle GET request with query params
                    Map<String, String> params = parseQueryParams(exchange);
                    String text = params.get("text");
                    String sizeStr = params.get("size");
                    
                    if (text == null || text.isEmpty()) {
                        sendErrorResponse(exchange, "Missing required parameter: text");
                        return;
                    }
                    
                    Integer size = null;
                    if (sizeStr != null && !sizeStr.isEmpty()) {
                        try {
                            size = Integer.parseInt(sizeStr);
                        } catch (NumberFormatException e) {
                            sendErrorResponse(exchange, "Invalid size parameter: " + sizeStr);
                            return;
                        }
                    }
                    
                    Map<String, Object> response = numberConversionService.convertNumber(text, size);
                    sendJsonResponse(exchange, response);
                } else if (isPostRequest(exchange)) {
                    // Handle POST request with JSON body
                    Map<String, Object> requestMap = parseJsonRequest(exchange);
                    
                    if (!requestMap.containsKey("text")) {
                        sendErrorResponse(exchange, "Missing required parameter: text");
                        return;
                    }
                    
                    String text = requestMap.get("text").toString();
                    Integer size = null;
                    
                    if (requestMap.containsKey("size")) {
                        try {
                            size = Integer.parseInt(requestMap.get("size").toString());
                        } catch (NumberFormatException e) {
                            sendErrorResponse(exchange, "Invalid size parameter");
                            return;
                        }
                    }
                    
                    Map<String, Object> response = numberConversionService.convertNumber(text, size);
                    sendJsonResponse(exchange, response);
                } else {
                    sendMethodNotAllowedResponse(exchange);
                }
            } catch (IOException e) {
                Msg.error(this, "Error handling number conversion request", e);
                try {
                    sendErrorResponse(exchange, "Internal server error: " + e.getMessage(), 500);
                } catch (IOException ex) {
                    Msg.error(this, "Failed to send error response", ex);
                }
            }
        });
    }

    /**
     * Gets or creates the NumberConversionService instance.
     *
     * @return The NumberConversionService instance
     */
    private NumberConversionService getOrCreateNumberConversionService() {
        NumberConversionService service = getService(NumberConversionService.SERVICE_NAME, NumberConversionService.class);
        if (service == null) {
            service = new NumberConversionService();
            // Register the service with the service registry
            plugin.getServiceRegistry().registerService(service);
        }
        return service;
    }
}