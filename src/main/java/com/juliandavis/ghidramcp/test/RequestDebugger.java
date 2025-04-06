package com.juliandavis.ghidramcp.test;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import ghidra.util.Msg;

/**
 * Helper class for debugging request format issues between Python and Java.
 * <p>
 * This class registers debugging endpoints that log and display request details.
 */
public class RequestDebugger {
    private final HttpServer server;
    private final GhidraMCPPlugin plugin;
    private final Gson gson;
    
    /**
     * Create a new RequestDebugger.
     * 
     * @param plugin the GhidraMCPPlugin instance
     */
    public RequestDebugger(GhidraMCPPlugin plugin) {
        this.plugin = plugin;
        this.server = plugin.getServerManager().getServer();
        this.gson = new GsonBuilder().setPrettyPrinting().create();
        
        // Register endpoint if server is available
        if (server != null) {
            registerEndpoints();
        } else {
            Msg.error(this, "Cannot register debug endpoints: server is null");
        }
    }
    
    /**
     * Register debugging endpoints.
     */
    private void registerEndpoints() {
        server.createContext("/debug/request", new RequestDebugHandler());
        server.createContext("/debug/echo", new EchoHandler());
        
        Msg.info(this, "Registered request debugging endpoints");
    }
    
    /**
     * Handler that logs details about requests.
     */
    private class RequestDebugHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            // Log request details
            String method = exchange.getRequestMethod();
            String path = exchange.getRequestURI().getPath();
            String query = exchange.getRequestURI().getQuery();
            String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
            
            StringBuilder debugInfo = new StringBuilder();
            debugInfo.append("Request Debug Info:\n");
            debugInfo.append("- Method: ").append(method).append("\n");
            debugInfo.append("- Path: ").append(path).append("\n");
            debugInfo.append("- Query: ").append(query).append("\n");
            debugInfo.append("- Content-Type: ").append(contentType).append("\n");
            
            // Read request body
            byte[] requestBodyBytes = exchange.getRequestBody().readAllBytes();
            String requestBody = new String(requestBodyBytes, StandardCharsets.UTF_8);
            
            debugInfo.append("- Body Length: ").append(requestBodyBytes.length).append(" bytes\n");
            debugInfo.append("- Body Content:\n").append(requestBody).append("\n");
            
            // Try to parse body as JSON if appropriate
            if (contentType != null && contentType.toLowerCase().contains("json")) {
                try {
                    Object jsonObject = gson.fromJson(requestBody, Object.class);
                    String formattedJson = gson.toJson(jsonObject);
                    debugInfo.append("- Parsed JSON:\n").append(formattedJson).append("\n");
                } catch (Exception e) {
                    debugInfo.append("- Failed to parse as JSON: ").append(e.getMessage()).append("\n");
                }
            }
            
            // Try to parse as form data
            if (contentType != null && contentType.toLowerCase().contains("form")) {
                debugInfo.append("- Form Parameters:\n");
                Map<String, String> formParams = parseFormParameters(requestBody);
                for (Map.Entry<String, String> entry : formParams.entrySet()) {
                    debugInfo.append("  - ").append(entry.getKey()).append(" = ").append(entry.getValue()).append("\n");
                }
            }
            
            // Log the debug info
            Msg.info(this, debugInfo.toString());
            
            // Send debug info as response
            sendTextResponse(exchange, debugInfo.toString());
        }
    }
    
    /**
     * Handler that echoes request data back to the client.
     */
    private class EchoHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            // Create map with request info
            Map<String, Object> responseMap = new HashMap<>();
            String method = exchange.getRequestMethod();
            String path = exchange.getRequestURI().getPath();
            String query = exchange.getRequestURI().getQuery();
            String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
            
            responseMap.put("method", method);
            responseMap.put("path", path);
            responseMap.put("query", query);
            responseMap.put("contentType", contentType);
            
            // Add headers
            Map<String, Object> headersMap = new HashMap<>();
            exchange.getRequestHeaders().forEach((key, values) -> {
                headersMap.put(key, values);
            });
            responseMap.put("headers", headersMap);
            
            // Read request body
            byte[] requestBodyBytes = exchange.getRequestBody().readAllBytes();
            String requestBody = new String(requestBodyBytes, StandardCharsets.UTF_8);
            responseMap.put("bodyLength", requestBodyBytes.length);
            responseMap.put("body", requestBody);
            
            // Try to parse body based on content type
            if (contentType != null) {
                if (contentType.toLowerCase().contains("json")) {
                    try {
                        Object jsonObject = gson.fromJson(requestBody, Object.class);
                        responseMap.put("parsedJson", jsonObject);
                    } catch (Exception e) {
                        responseMap.put("jsonError", e.getMessage());
                    }
                } else if (contentType.toLowerCase().contains("form")) {
                    Map<String, String> formParams = parseFormParameters(requestBody);
                    responseMap.put("formParams", formParams);
                }
            }
            
            // Create standardized response
            Map<String, Object> standardResponse = new HashMap<>();
            standardResponse.put("status", "success");
            standardResponse.put("data", responseMap);
            
            // Send JSON response
            String json = gson.toJson(standardResponse);
            sendJsonResponse(exchange, json);
        }
    }
    
    /**
     * Parse form parameters from request body.
     * 
     * @param requestBody the request body
     * @return a map of form parameters
     */
    private Map<String, String> parseFormParameters(String requestBody) {
        Map<String, String> params = new HashMap<>();
        
        if (requestBody != null && !requestBody.isEmpty()) {
            for (String param : requestBody.split("&")) {
                String[] pair = param.split("=", 2);
                if (pair.length > 1) {
                    try {
                        String key = java.net.URLDecoder.decode(pair[0], StandardCharsets.UTF_8);
                        String value = java.net.URLDecoder.decode(pair[1], StandardCharsets.UTF_8);
                        params.put(key, value);
                    } catch (Exception e) {
                        Msg.warn(this, "Error decoding form parameter: " + e.getMessage());
                        params.put(pair[0], pair[1]);
                    }
                } else if (pair.length == 1) {
                    try {
                        String key = java.net.URLDecoder.decode(pair[0], StandardCharsets.UTF_8);
                        params.put(key, "");
                    } catch (Exception e) {
                        Msg.warn(this, "Error decoding form parameter: " + e.getMessage());
                        params.put(pair[0], "");
                    }
                }
            }
        }
        
        return params;
    }
    
    /**
     * Send a text response to the client.
     * 
     * @param exchange the HTTP exchange
     * @param text the text to send
     * @throws IOException if an I/O error occurs
     */
    private void sendTextResponse(HttpExchange exchange, String text) throws IOException {
        byte[] response = text.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=UTF-8");
        exchange.sendResponseHeaders(200, response.length);
        
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(response);
        }
    }
    
    /**
     * Send a JSON response to the client.
     * 
     * @param exchange the HTTP exchange
     * @param json the JSON string to send
     * @throws IOException if an I/O error occurs
     */
    private void sendJsonResponse(HttpExchange exchange, String json) throws IOException {
        byte[] response = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(200, response.length);
        
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(response);
        }
    }
}
