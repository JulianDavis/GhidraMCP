package com.juliandavis.ghidramcp.api.handlers;

import java.io.IOException;
import java.util.Map;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import com.juliandavis.ghidramcp.services.DecompileService;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ghidra.util.Msg;

/**
 * HTTP handler for decompilation operations in the GhidraMCP plugin.
 * <p>
 * This handler exposes endpoints for decompiling code, identifying functions, and managing functions.
 */
public class DecompileHttpHandler extends BaseHttpHandler {
    
    private final DecompileService decompileService;
    
    /**
     * Create a new DecompileHttpHandler.
     * 
     * @param plugin the GhidraMCPPlugin instance
     */
    public DecompileHttpHandler(GhidraMCPPlugin plugin) {
        super(plugin);
        
        // Get or create the DecompileService
        decompileService = getOrCreateDecompileService();
    }
    
    private DecompileService getOrCreateDecompileService() {
        // Try to get the existing service
        DecompileService service = ServiceRegistry.getInstance().getService(
                DecompileService.SERVICE_NAME, DecompileService.class);
        
        // If it doesn't exist, create and register it
        if (service == null) {
            service = new DecompileService();
            ServiceRegistry.getInstance().registerService(service);
        }
        
        return service;
    }
    
    @Override
    public void registerEndpoints() {
        HttpServer server = getServer();
        if (server == null) {
            Msg.error(this, "Cannot register endpoints: server is null");
            return;
        }
        
        // Register all endpoints
        server.createContext("/decompile", this::handleDecompileFunction);
        server.createContext("/decompileRange", this::handleDecompileAddressRange);
        server.createContext("/identifyFunction", this::handleIdentifyFunction);
        server.createContext("/defineFunction", this::handleDefineFunction);
        server.createContext("/renameFunction", this::handleRenameFunction);
        server.createContext("/renameData", this::handleRenameData);
        
        Msg.info(this, "Registered Decompile endpoints");
    }
    
    /**
     * Handle decompile function request.
     */
    private void handleDecompileFunction(HttpExchange exchange) throws IOException {
        if (!isPostRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        // Read the function name from the request body
        String name = new String(exchange.getRequestBody().readAllBytes());
        
        if (name == null || name.isEmpty()) {
            sendErrorResponse(exchange, "Function name is required");
            return;
        }
        
        Map<String, Object> result = decompileService.decompileFunctionByName(name);
        sendJsonResponse(exchange, result);
    }
    
    /**
     * Handle decompile address range request.
     */
    private void handleDecompileAddressRange(HttpExchange exchange) throws IOException {
        if (!isPostRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        // Parse parameters from the request
        Map<String, String> params = parsePostParams(exchange);
        String startAddress = params.get("startAddress");
        String endAddress = params.get("endAddress");
        
        // Validate parameters
        if (startAddress == null || startAddress.isEmpty()) {
            sendErrorResponse(exchange, "Start address is required");
            return;
        }
        
        if (endAddress == null || endAddress.isEmpty()) {
            sendErrorResponse(exchange, "End address is required");
            return;
        }
        
        Map<String, Object> result = decompileService.decompileAddressRange(startAddress, endAddress);
        sendJsonResponse(exchange, result);
    }
    
    /**
     * Handle identify function request.
     */
    private void handleIdentifyFunction(HttpExchange exchange) throws IOException {
        if (!isGetRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        // Parse parameters from the query string
        Map<String, String> params = parseQueryParams(exchange);
        String address = params.get("address");
        
        // Validate parameters
        if (address == null || address.isEmpty()) {
            sendErrorResponse(exchange, "Address is required");
            return;
        }
        
        Map<String, Object> result = decompileService.identifyFunctionAtAddress(address);
        sendJsonResponse(exchange, result);
    }
    
    /**
     * Handle define function request.
     */
    private void handleDefineFunction(HttpExchange exchange) throws IOException {
        if (!isPostRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        // Parse parameters from the request
        Map<String, String> params = parsePostParams(exchange);
        String address = params.get("address");
        String name = params.get("name"); // Optional function name
        boolean force = Boolean.parseBoolean(params.getOrDefault("force", "false")); // Force creation flag
        
        // Validate parameters
        if (address == null || address.isEmpty()) {
            sendErrorResponse(exchange, "Address is required");
            return;
        }
        
        Map<String, Object> result = decompileService.defineFunctionAtAddress(address, name, force);
        sendJsonResponse(exchange, result);
    }
    
    /**
     * Handle rename function request.
     */
    private void handleRenameFunction(HttpExchange exchange) throws IOException {
        if (!isPostRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        // Parse parameters from the request
        Map<String, String> params = parsePostParams(exchange);
        String oldName = params.get("oldName");
        String newName = params.get("newName");
        
        // Validate parameters
        if (oldName == null || oldName.isEmpty()) {
            sendErrorResponse(exchange, "Old function name is required");
            return;
        }
        
        if (newName == null || newName.isEmpty()) {
            sendErrorResponse(exchange, "New function name is required");
            return;
        }
        
        Map<String, Object> result = decompileService.renameFunction(oldName, newName);
        sendJsonResponse(exchange, result);
    }
    
    /**
     * Handle rename data request.
     */
    private void handleRenameData(HttpExchange exchange) throws IOException {
        if (!isPostRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        // Parse parameters from the request
        Map<String, String> params = parsePostParams(exchange);
        String address = params.get("address");
        String newName = params.get("newName");
        
        // Validate parameters
        if (address == null || address.isEmpty()) {
            sendErrorResponse(exchange, "Address is required");
            return;
        }
        
        if (newName == null || newName.isEmpty()) {
            sendErrorResponse(exchange, "New name is required");
            return;
        }
        
        Map<String, Object> result = decompileService.renameDataAtAddress(address, newName);
        sendJsonResponse(exchange, result);
    }
}
