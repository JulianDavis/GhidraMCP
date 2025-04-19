package com.juliandavis.ghidramcp.api.handlers;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.services.NamespaceService;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.IOException;
import java.util.Map;

/**
 * HTTP handler for namespace operations.
 * <p>
 * This handler exposes endpoints for creating and manipulating namespaces.
 */
public class NamespaceHttpHandler extends BaseHttpHandler {

    /**
     * Create a new NamespaceHttpHandler with the specified plugin.
     *
     * @param plugin the GhidraMCPPlugin instance
     */
    public NamespaceHttpHandler(GhidraMCPPlugin plugin) {
        super(plugin);
    }

    @Override
    public void registerEndpoints() {
        HttpServer server = getServer();
        if (server == null) {
            Msg.error(this, "HTTP Server not available for registering Namespace endpoints.");
            return;
        }

        server.createContext("/namespace/create", this::handleCreateNamespace);
        Msg.info(this, "Registered endpoint: /namespace/create");
    }

    /**
     * Handle requests to create a namespace.
     *
     * @param exchange the HTTP exchange
     * @throws IOException if an I/O error occurs
     */
    private void handleCreateNamespace(HttpExchange exchange) throws IOException {
        if (!isPostRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }

        Program currentProgram = getCurrentProgram();
        if (currentProgram == null) {
            sendErrorResponse(exchange, "Service Unavailable: No active program.", 503);
            return;
        }

        NamespaceService namespaceService = getService(
            NamespaceService.SERVICE_NAME,
            NamespaceService.class
        );

        if (namespaceService == null) {
            sendErrorResponse(exchange, "NamespaceService not available.", 503);
            return;
        }

        Map<String, String> params = parsePostParams(exchange);
        String path = params.get("path");
        String source = params.get("source");

        if (path == null || path.isEmpty()) {
            sendErrorResponse(exchange, "Missing required parameter: path", 400);
            return;
        }

        // Call the service method
        Map<String, Object> result = namespaceService.createNamespace(path, source);

        // Send the appropriate response based on the result
        if ("error".equals(result.get("status"))) {
            int statusCode = 400; // Default
            String message = "An error occurred."; // Default

            if (result.containsKey("error") && result.get("error") instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> errorDetails = (Map<String, Object>) result.get("error");
                if (errorDetails.containsKey("code") && errorDetails.get("code") instanceof Number) {
                    statusCode = ((Number) errorDetails.get("code")).intValue();
                }
                if (errorDetails.containsKey("message") && errorDetails.get("message") instanceof String) {
                    message = (String) errorDetails.get("message");
                }
            }
            sendErrorResponse(exchange, message, statusCode);
        } else {
            // Send success response using base class helper
            sendJsonResponse(exchange, result);
        }
    }
}
