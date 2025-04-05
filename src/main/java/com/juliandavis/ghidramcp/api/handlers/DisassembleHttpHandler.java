package com.juliandavis.ghidramcp.api.handlers;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import com.juliandavis.ghidramcp.services.DisassembleService;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ghidra.program.model.listing.CodeUnit;
import ghidra.util.Msg;

/**
 * HTTP handler for disassembly operations in the GhidraMCP plugin.
 * <p>
 * This handler exposes endpoints for disassembling code and managing assembly-level operations.
 */
public class DisassembleHttpHandler extends BaseHttpHandler {
    
    private final DisassembleService disassembleService;
    
    /**
     * Create a new DisassembleHttpHandler.
     * 
     * @param plugin the GhidraMCPPlugin instance
     */
    public DisassembleHttpHandler(GhidraMCPPlugin plugin) {
        super(plugin);
        
        // Get or create the DisassembleService
        disassembleService = getOrCreateDisassembleService();
    }
    
    private DisassembleService getOrCreateDisassembleService() {
        // Try to get the existing service
        DisassembleService service = ServiceRegistry.getInstance().getService(
                DisassembleService.SERVICE_NAME, DisassembleService.class);
        
        // If it doesn't exist, create and register it
        if (service == null) {
            service = new DisassembleService();
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
        server.createContext("/disassemble", this::handleDisassembleAtAddress);
        server.createContext("/disassembleFunction", this::handleDisassembleFunction);
        server.createContext("/setComment", this::handleSetComment);
        
        Msg.info(this, "Registered Disassemble endpoints");
    }
    
    /**
     * Handle disassemble at address request.
     */
    private void handleDisassembleAtAddress(HttpExchange exchange) throws IOException {
        if (!isGetRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        // Parse parameters from the query string
        Map<String, String> params = parseQueryParams(exchange);
        String address = params.get("address");
        int length = parseIntOrDefault(params.get("length"), 10);  // Default to 10 instructions
        
        // Validate parameters
        if (address == null || address.isEmpty()) {
            sendErrorResponse(exchange, "Address is required");
            return;
        }
        
        if (length <= 0) {
            sendErrorResponse(exchange, "Instruction count must be positive");
            return;
        }
        
        Map<String, Object> result = disassembleService.getDisassemblyAtAddress(address, length);
        sendJsonResponse(exchange, result);
    }
    
    /**
     * Handle disassemble function request.
     */
    private void handleDisassembleFunction(HttpExchange exchange) throws IOException {
        if (!isPostRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        // Read the function name from the request body
        String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        
        // Validate parameters
        if (name == null || name.isEmpty()) {
            sendErrorResponse(exchange, "Function name is required");
            return;
        }
        
        Map<String, Object> result = disassembleService.getDisassemblyForFunction(name);
        sendJsonResponse(exchange, result);
    }
    
    /**
     * Handle set comment request.
     */
    private void handleSetComment(HttpExchange exchange) throws IOException {
        if (!isPostRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        // Parse parameters from the request
        Map<String, String> params = parsePostParams(exchange);
        String address = params.get("address");
        String comment = params.get("comment");
        int commentType = parseIntOrDefault(params.get("type"), CodeUnit.EOL_COMMENT); // Default to end-of-line comment
        
        // Validate parameters
        if (address == null || address.isEmpty()) {
            sendErrorResponse(exchange, "Address is required");
            return;
        }
        
        // Comment can be empty (to clear a comment)
        if (comment == null) {
            comment = "";
        }
        
        // Validate comment type
        if (commentType != CodeUnit.PLATE_COMMENT &&
                commentType != CodeUnit.PRE_COMMENT &&
                commentType != CodeUnit.EOL_COMMENT &&
                commentType != CodeUnit.POST_COMMENT &&
                commentType != CodeUnit.REPEATABLE_COMMENT) {
            
            sendErrorResponse(exchange, "Invalid comment type: " + commentType);
            return;
        }
        
        Map<String, Object> result = disassembleService.setCommentAtAddress(address, comment, commentType);
        sendJsonResponse(exchange, result);
    }
}
