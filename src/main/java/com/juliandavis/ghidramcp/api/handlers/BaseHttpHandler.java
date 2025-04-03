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
import com.sun.net.httpserver.HttpServer;

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
     * Send a JSON response to the client.
     * 
     * @param exchange the HTTP exchange
     * @param responseMap the response map to serialize as JSON
     */
    protected void sendJsonResponse(HttpExchange exchange, Map<String, Object> responseMap) {
        sendJsonResponse(exchange, (Object) responseMap);
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
     * Send an error response.
     * 
     * @param exchange the HTTP exchange
     * @param message the error message
     * @throws IOException if an I/O error occurs
     */
    protected void sendErrorResponse(HttpExchange exchange, String message) throws IOException {
        Map<String, Object> error = createErrorResponse(message);
        
        byte[] responseBytes = plugin.getGson().toJson(error).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(400, responseBytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }
    
    /**
     * Send a method not allowed response.
     * 
     * @param exchange the HTTP exchange
     * @throws IOException if an I/O error occurs
     */
    protected void sendMethodNotAllowedResponse(HttpExchange exchange) throws IOException {
        Map<String, Object> error = createErrorResponse("Method not allowed");
        
        byte[] responseBytes = plugin.getGson().toJson(error).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(405, responseBytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }
    
    /**
     * Register endpoints for this handler with the HTTP server.
     * <p>
     * This method should be implemented by subclasses to register their endpoints.
     */
    public abstract void registerEndpoints();
    
    /**
     * Get the plugin instance.
     * 
     * @return the GhidraMCPPlugin instance
     */
    protected GhidraMCPPlugin getPlugin() {
        return plugin;
    }
    
    /**
     * Parse query parameters from the exchange.
     * 
     * @param exchange the HTTP exchange
     * @return a map of query parameters
     */
    protected Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> queryParams = new HashMap<>();
        String query = exchange.getRequestURI().getQuery();
        
        if (query != null && !query.isEmpty()) {
            for (String param : query.split("&")) {
                String[] pair = param.split("=");
                if (pair.length > 1) {
                    queryParams.put(pair[0], pair[1]);
                } else {
                    queryParams.put(pair[0], "");
                }
            }
        }
        
        return queryParams;
    }
    
    /**
     * Parse POST parameters from the exchange.
     * 
     * @param exchange the HTTP exchange
     * @return a map of POST parameters
     * @throws IOException if an I/O error occurs
     */
    protected Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        String requestBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        Map<String, String> postParams = new HashMap<>();
        
        if (!requestBody.isEmpty()) {
            for (String param : requestBody.split("&")) {
                String[] pair = param.split("=");
                if (pair.length > 1) {
                    postParams.put(pair[0], pair[1]);
                } else {
                    postParams.put(pair[0], "");
                }
            }
        }
        
        return postParams;
    }
    
    /**
     * Get the HTTP server instance from the plugin.
     * 
     * @return the HTTP server instance
     */
    protected HttpServer getServer() {
        return plugin.getServerManager().getServer();
    }
    
    /**
     * Check if the request is a GET request.
     * 
     * @param exchange the HTTP exchange
     * @return true if the request is a GET request, false otherwise
     */
    protected boolean isGetRequest(HttpExchange exchange) {
        return "GET".equals(exchange.getRequestMethod());
    }
    
    /**
     * Check if the request is a POST request.
     * 
     * @param exchange the HTTP exchange
     * @return true if the request is a POST request, false otherwise
     */
    protected boolean isPostRequest(HttpExchange exchange) {
        return "POST".equals(exchange.getRequestMethod());
    }
    
    /**
     * Parse an integer from a string with a default value.
     * 
     * @param value the string to parse
     * @param defaultValue the default value to use if parsing fails
     * @return the parsed integer or the default value
     */
    protected int parseIntOrDefault(String value, int defaultValue) {
        if (value == null) {
            return defaultValue;
        }
        
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }
}
