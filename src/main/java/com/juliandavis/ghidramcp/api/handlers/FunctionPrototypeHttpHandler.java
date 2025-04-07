package com.juliandavis.ghidramcp.api.handlers;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import com.juliandavis.ghidramcp.services.FunctionPrototypeService;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ghidra.util.Msg;

/**
 * HTTP handler for function prototype (signature) operations in the GhidraMCP plugin.
 * <p>
 * This handler exposes endpoints for setting and manipulating function signatures.
 */
public class FunctionPrototypeHttpHandler extends BaseHttpHandler {

    private final FunctionPrototypeService functionPrototypeService;

    /**
     * Create a new FunctionPrototypeHttpHandler.
     *
     * @param plugin the GhidraMCPPlugin instance
     */
    public FunctionPrototypeHttpHandler(GhidraMCPPlugin plugin) {
        super(plugin);

        // Get or create the FunctionPrototypeService
        functionPrototypeService = getOrCreateFunctionPrototypeService();
    }

    private FunctionPrototypeService getOrCreateFunctionPrototypeService() {
        // Try to get the existing service
        FunctionPrototypeService service = ServiceRegistry.getInstance().getService(
                FunctionPrototypeService.SERVICE_NAME, FunctionPrototypeService.class);

        // If it doesn't exist, create and register it
        if (service == null) {
            // Ensure we have the plugin instance to get the tool
            if (plugin == null) {
                 // This shouldn't happen if the handler is constructed correctly, but handle defensively
                 Msg.error(this, "Cannot create FunctionPrototypeService: GhidraMCPPlugin instance is null.");
                 // Depending on desired behavior, could throw an exception or return null
                 return null; // Or throw new IllegalStateException(...)
            }
            service = new FunctionPrototypeService(plugin.getTool()); // Pass PluginTool to constructor
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

        // Register endpoints
        server.createContext("/set_function_prototype", this::handleSetFunctionPrototype);

        Msg.info(this, "Registered Function Prototype endpoints");
    }

    /**
     * Handle set function prototype request.
     */
    private void handleSetFunctionPrototype(HttpExchange exchange) throws IOException {
        if (!isPostRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }

        // Parse JSON request body
        Map<String, Object> params = parseJsonRequest(exchange);

        // Extract required parameters
        String functionName = (String) params.get("functionName");
        String returnType = (String) params.get("returnType");
        String callingConvention = (String) params.get("callingConvention"); // Optional
        // Extract renameOption string (replacing forceUpdate)
        // Default to "RENAME_IF_DEFAULT" if not provided or empty
        String renameOptionStr = (String) params.getOrDefault("rename_option", "RENAME_IF_DEFAULT");
        if (renameOptionStr == null || renameOptionStr.trim().isEmpty()) {
            renameOptionStr = "RENAME_IF_DEFAULT";
        }
        // String updateTypeStr = (String) params.getOrDefault("updateType", "DYNAMIC_STORAGE_ALL_PARAMS"); // REMOVED

        // Extract parameters array
        List<Map<String, String>> parameterDefinitions = new ArrayList<>();
        Object parametersObj = params.get("parameters");

        if (parametersObj instanceof List) {
            @SuppressWarnings("unchecked")
            List<Object> paramsList = (List<Object>) parametersObj;

            for (Object paramObj : paramsList) {
                if (paramObj instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> paramMap = (Map<String, Object>) paramObj;

                    Map<String, String> paramDef = new HashMap<>();
                    paramDef.put("name", (String) paramMap.get("name"));
                    paramDef.put("type", (String) paramMap.get("type"));
                    // Extract optional storage string
                    paramDef.put("storage", (String) paramMap.get("storage")); // Will be null if not present

                    parameterDefinitions.add(paramDef);
                }
            }
        }

        // Validate required parameters
        if (functionName == null || functionName.isEmpty()) {
            sendErrorResponse(exchange, "Function name is required");
            return;
        }

        if (returnType == null || returnType.isEmpty()) {
            sendErrorResponse(exchange, "Return type is required");
            return;
        }

        // Call the service to set the function prototype
        // Call the service (updateTypeStr removed)
        Map<String, Object> result = functionPrototypeService.setFunctionPrototype(
                functionName, returnType, parameterDefinitions, callingConvention, renameOptionStr);

        sendJsonResponse(exchange, result);
    }
}
