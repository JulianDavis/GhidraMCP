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

    // Service instance will be retrieved from the registry on demand in handler methods
    // private final FunctionPrototypeService functionPrototypeService; // Removed final field

    /**
     * Create a new FunctionPrototypeHttpHandler.
     *
     * @param plugin the GhidraMCPPlugin instance
     */
    public FunctionPrototypeHttpHandler(GhidraMCPPlugin plugin) {
        super(plugin);

        // Get or create the FunctionPrototypeService
        // Constructor no longer initializes the service field
        // functionPrototypeService = getOrCreateFunctionPrototypeService();
    }

    // Removed getOrCreateFunctionPrototypeService method - service retrieval happens in handlers

    @Override
    public void registerEndpoints() {
        HttpServer server = getServer();
        if (server == null) {
            Msg.error(this, "Cannot register endpoints: server is null");
            return;
        }

        // Register endpoints
        server.createContext("/set_function_prototype", this::handleSetFunctionPrototype);
        server.createContext("/apply_function_data_types", this::handleApplyFunctionDataTypes);

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
        // Retrieve service instance
        FunctionPrototypeService service = getService(FunctionPrototypeService.SERVICE_NAME, FunctionPrototypeService.class);
        if (service == null) {
            sendErrorResponse(exchange, FunctionPrototypeService.SERVICE_NAME + " not available.", 503);
            return;
        }
        Map<String, Object> result = service.setFunctionPrototype(
                functionName, returnType, parameterDefinitions, callingConvention, renameOptionStr);

        sendJsonResponse(exchange, result);
    }

    /**
     * Handle apply function data types request.
     */
    private void handleApplyFunctionDataTypes(HttpExchange exchange) throws IOException {
        if (!isPostRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }

        // Parse JSON request body
        Map<String, Object> params = parseJsonRequest(exchange);

        // Extract required parameters
        String functionAddress = (String) params.get("function_address");
        
        // Extract optional parameters with defaults
        boolean alwaysReplace = Boolean.parseBoolean(String.valueOf(params.getOrDefault("always_replace", "true")));
        boolean createBookmarks = Boolean.parseBoolean(String.valueOf(params.getOrDefault("create_bookmarks", "true")));

        // Validate required parameters
        if (functionAddress == null || functionAddress.isEmpty()) {
            sendErrorResponse(exchange, "Function address is required");
            return;
        }

        // Retrieve service instance
        FunctionPrototypeService service = getService(FunctionPrototypeService.SERVICE_NAME, FunctionPrototypeService.class);
        if (service == null) {
            sendErrorResponse(exchange, FunctionPrototypeService.SERVICE_NAME + " not available.", 503);
            return;
        }
        
        // Call the service to apply function data types
        Map<String, Object> result = service.applyFunctionDataTypes(
                functionAddress, alwaysReplace, createBookmarks);

        sendJsonResponse(exchange, result);
    }
}
