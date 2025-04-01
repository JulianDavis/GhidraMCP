package com.juliandavis.ghidramcp.api.handlers;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.core.service.Service;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import com.sun.net.httpserver.HttpExchange;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Base class for all HTTP handlers in the GhidraMCP plugin.
 * <p>
 * This class provides common functionality for all handlers, including:
 * <ul>
 * <li>Access to the plugin instance</li>
 * <li>Methods for sending responses</li>
 * <li>Methods for parsing request parameters</li>
 * <li>Access to registered services</li>
 * </ul>
 */
public abstract class BaseHttpHandler {
    
    protected final GhidraMCPPlugin plugin;
    
    /**
     * Create a new BaseHttpHandler with the specified plugin.
     * 
     * @param plugin the GhidraMCPPlugin instance
     */
    public BaseHttpHandler(GhidraMCPPlugin plugin) {
        this.plugin = plugin;
    }
    
    /**
     * Get the current program from the service registry.
     * 
     * @return the current program, or null if no program is loaded
     */
    protected Program getCurrentProgram() {
        return ServiceRegistry.getInstance().getCurrentProgram();
    }
    
    /**
     * Get a service from the service registry.
     * 
     * @param <T> the expected service type
     * @param serviceName the name of the service
     * @param serviceClass the class of the service
     * @return the service, or null if not found or not of the expected type
     */
    protected <T extends Service> T getService(String serviceName, Class<T> serviceClass) {
        return ServiceRegistry.getInstance().getService(serviceName, serviceClass);
    }
    
    /**
     * Send a JSON response to the client.
     * 
     * @param exchange the HTTP exchange
     * @param response the response object to serialize as JSON
     */
    protected void sendJsonResponse(HttpExchange exchange, Object response) {
        try {
            String json = plugin.getGson().toJson(response);
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        } catch (IOException e) {
            Msg.error(this, "Failed to send JSON response", e);
        }
    }
    
    /**
     * Create a standardized error response.
     * 
     * @param message the error message
     * @return a map containing the error response
     */
    protected Map<String, Object> createErrorResponse(String message) {
        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("error", message);
        return response;
    }
    
    /**
     * Create a standardized success response.
     * 
     * @param data the data to include in the response
     * @return a map containing the success response
     */
    protected Map<String, Object> createSuccessResponse(Object data) {
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("data", data);
        return response;
    }
    
    /**
     * Register endpoints for this handler with the HTTP server.
     * <p>
     * This method should be implemented by subclasses to register their endpoints.
     */
    public abstract void registerEndpoints();
}
