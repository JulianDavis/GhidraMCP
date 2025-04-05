package com.juliandavis.ghidramcp.api.handlers;

import java.io.IOException;
import java.util.Map;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import com.juliandavis.ghidramcp.services.FunctionXrefService;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ghidra.util.Msg;

/**
 * HTTP handler for function and address cross-reference operations in the GhidraMCP plugin.
 * <p>
 * This handler exposes endpoints for retrieving cross-references (xrefs) to and from addresses.
 */
public class FunctionXrefHttpHandler extends BaseHttpHandler {
    
    private final FunctionXrefService functionXrefService;
    
    /**
     * Create a new FunctionXrefHttpHandler.
     * 
     * @param plugin the GhidraMCPPlugin instance
     */
    public FunctionXrefHttpHandler(GhidraMCPPlugin plugin) {
        super(plugin);
        
        // Get or create the FunctionXrefService
        functionXrefService = getOrCreateFunctionXrefService();
    }
    
    private FunctionXrefService getOrCreateFunctionXrefService() {
        // Try to get the existing service
        FunctionXrefService service = ServiceRegistry.getInstance().getService(
                FunctionXrefService.SERVICE_NAME, FunctionXrefService.class);
        
        // If it doesn't exist, create and register it
        if (service == null) {
            service = new FunctionXrefService();
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
        server.createContext("/xrefs", this::handleXrefsAtAddress);
        
        Msg.info(this, "Registered Function Xref endpoints");
    }
    
    /**
     * Handle xrefs at address request.
     */
    private void handleXrefsAtAddress(HttpExchange exchange) throws IOException {
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
        
        Map<String, Object> result = functionXrefService.getReferencesAtAddress(address);
        sendJsonResponse(exchange, result);
    }
}
