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

    // Service instance will be retrieved from the registry on demand in handler methods
    // private final FunctionXrefService functionXrefService; // Removed final field

    /**
     * Create a new FunctionXrefHttpHandler.
     *
     * @param plugin the GhidraMCPPlugin instance
     */
    public FunctionXrefHttpHandler(GhidraMCPPlugin plugin) {
        super(plugin);

        // Get or create the FunctionXrefService
        // Constructor no longer initializes the service field
        // functionXrefService = getOrCreateFunctionXrefService();
    }

    // Removed getOrCreateFunctionXrefService method - service retrieval happens in handlers

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

        // Retrieve service instance
        FunctionXrefService service = getService(FunctionXrefService.SERVICE_NAME, FunctionXrefService.class);
        if (service == null) {
            sendErrorResponse(exchange, FunctionXrefService.SERVICE_NAME + " not available.", 503);
            return;
        }
        Map<String, Object> result = service.getReferencesAtAddress(address);
        sendJsonResponse(exchange, result);
    }
}
