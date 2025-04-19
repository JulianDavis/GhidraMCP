package com.juliandavis.ghidramcp.api.handlers;

import com.juliandavis.ghidramcp.GhidraMCPPlugin; // Import plugin class
import com.juliandavis.ghidramcp.services.MemoryManipulationService;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer; // Keep for getServer().createContext
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.IOException;
import java.util.Map;

public class MemoryManipulationHttpHandler extends BaseHttpHandler {

    // No need to store service instance here, get it from registry on demand

    // Constructor now takes only the plugin instance
    public MemoryManipulationHttpHandler(GhidraMCPPlugin plugin) {
        super(plugin); // Call base constructor
        // No need to instantiate service here
        // Registration happens via GhidraMCPPlugin calling registerEndpoints
    }

    // Remove programActivated and programDeactivated methods

    @Override
    public void registerEndpoints() {
        HttpServer server = getServer();
        if (server == null) {
             Msg.error(this, "HTTP Server not available for registering MemoryManipulation endpoints.");
             return;
        }
        // Clear memory range
        server.createContext("/memory/clear", this::handleClearMemoryRange);
        Msg.info(this, "Registered endpoint: /memory/clear");

        server.createContext("/function/create", this::handleCreateFunction);
        Msg.info(this, "Registered endpoint: /function/create");
    }

    // Remove createHandlerError, use base class createErrorResponse

    private void handleClearMemoryRange(HttpExchange exchange) throws IOException {
         if (!isPostRequest(exchange)) { // Use base class helper
            sendMethodNotAllowedResponse(exchange); // Use base class helper
            return;
        }

        // Get current program using base class method
        Program currentProgram = getCurrentProgram();
        if (currentProgram == null) {
             sendErrorResponse(exchange, "Service Unavailable: No active program.", 503);
             return;
        }

        // Get the service from the registry
        MemoryManipulationService memoryService = getService(
            MemoryManipulationService.SERVICE_NAME,
            MemoryManipulationService.class
        );

        if (memoryService == null) {
             sendErrorResponse(exchange, "MemoryManipulationService not available.", 503);
             return;
        }

        // Parse parameters using base class helper
        Map<String, String> params = parsePostParams(exchange);
        String startAddressStr = params.get("start_address");
        String endAddressStr = params.get("end_address");

        if (startAddressStr == null || startAddressStr.isEmpty() || endAddressStr == null || endAddressStr.isEmpty()) {
            sendErrorResponse(exchange, "Missing required parameters: start_address, end_address", 400);
            return;
        }

        // Call the service method
        Map<String, Object> result = memoryService.clearMemoryRange(startAddressStr, endAddressStr);

        // Check the status field in the result map and send appropriate response
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
            sendErrorResponse(exchange, message, statusCode); // Use base class helper
        } else {
            // Send success response using base class helper
            // The service already wrapped the data correctly, so just pass the result map
            sendJsonResponse(exchange, result);
        }
    }

    private void handleCreateFunction(HttpExchange exchange) throws IOException {
         if (!isPostRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }

        Program currentProgram = getCurrentProgram();
        if (currentProgram == null) {
             sendErrorResponse(exchange, "Service Unavailable: No active program.", 503);
             return;
        }

        MemoryManipulationService memoryService = getService(
            MemoryManipulationService.SERVICE_NAME,
            MemoryManipulationService.class
        );

        if (memoryService == null) {
             sendErrorResponse(exchange, "MemoryManipulationService not available.", 503);
             return;
        }

        Map<String, String> params = parsePostParams(exchange);
        String addressStr = params.get("address"); // Expect 'address' parameter

        if (addressStr == null || addressStr.isEmpty()) {
            sendErrorResponse(exchange, "Missing required parameter: address", 400);
            return;
        }

        // Call the service method
        Map<String, Object> result = memoryService.createFunctionAtAddress(addressStr);

        // Check the status field in the result map and send appropriate response
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
