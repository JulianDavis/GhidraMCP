package com.juliandavis.ghidramcp.api.handlers;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.services.ProgramInfoService;
import com.sun.net.httpserver.HttpExchange;
import ghidra.util.Msg;

import java.io.IOException;
import java.util.Map;

/**
 * HTTP handler for program information operations.
 * <p>
 * This handler exposes endpoints for retrieving program metadata, functions,
 * namespaces, segments, imports, exports, and other program information.
 */
public class ProgramInfoHttpHandler extends BaseHttpHandler {

    private final ProgramInfoService programInfoService;

    /**
     * Constructor for the ProgramInfoHttpHandler.
     *
     * @param plugin The GhidraMCPPlugin instance
     */
    public ProgramInfoHttpHandler(GhidraMCPPlugin plugin) {
        super(plugin);
        this.programInfoService = getOrCreateProgramInfoService();
    }
    
    /**
     * Register all endpoints for this handler.
     */
    @Override
    public void registerEndpoints() {
        // Register program information endpoints
        getServer().createContext("/programInfo", this::handleGetProgramInfo);
        getServer().createContext("/methods", this::handleGetMethods);
        getServer().createContext("/programInfo/functionStats", this::handleGetFunctionStats);
        getServer().createContext("/programInfo/symbolStats", this::handleGetSymbolStats);
        getServer().createContext("/programInfo/dataTypeStats", this::handleGetDataTypeStats);
        getServer().createContext("/segments", this::handleGetSegments);
        getServer().createContext("/imports", this::handleGetImports);
        getServer().createContext("/exports", this::handleGetExports);
        getServer().createContext("/namespaces", this::handleGetNamespaces);
        getServer().createContext("/classes", this::handleGetClasses);
        getServer().createContext("/data", this::handleGetData);
        getServer().createContext("/searchFunctions", this::handleSearchFunctions);
        
        Msg.info(this, "Registered program information endpoints");
    }
    
    /**
     * Handle get program info request
     */
    private void handleGetProgramInfo(HttpExchange exchange) throws IOException {
        if (!isGetRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        Map<String, String> params = parseQueryParams(exchange);
        boolean includeDetailedStats = "full".equals(params.get("detail"));
        
        sendJsonResponse(exchange, programInfoService.getProgramMetadata(includeDetailedStats));
    }
    
    /**
     * Handle get all function names request
     */
    private void handleGetMethods(HttpExchange exchange) throws IOException {
        if (!isGetRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        Map<String, String> params = parseQueryParams(exchange);
        int offset = parseIntOrDefault(params.get("offset"), 0);
        int limit = parseIntOrDefault(params.get("limit"), 100);
        
        sendJsonResponse(exchange, programInfoService.getAllFunctionNames(offset, limit));
    }
    
    /**
     * Handle get function statistics request
     */
    private void handleGetFunctionStats(HttpExchange exchange) throws IOException {
        if (!isGetRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        Map<String, String> params = parseQueryParams(exchange);
        String continuationToken = params.get("continuationToken");
        int limit = parseIntOrDefault(params.get("limit"), 500);
        
        sendJsonResponse(exchange, programInfoService.getFunctionStats(continuationToken, limit));
    }
    
    /**
     * Handle get segments request
     */
    private void handleGetSegments(HttpExchange exchange) throws IOException {
        if (!isGetRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        Map<String, String> params = parseQueryParams(exchange);
        int offset = parseIntOrDefault(params.get("offset"), 0);
        int limit = parseIntOrDefault(params.get("limit"), 100);
        
        sendJsonResponse(exchange, programInfoService.listSegments(offset, limit));
    }
    
    /**
     * Handle get imports request
     */
    private void handleGetImports(HttpExchange exchange) throws IOException {
        if (!isGetRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        Map<String, String> params = parseQueryParams(exchange);
        int offset = parseIntOrDefault(params.get("offset"), 0);
        int limit = parseIntOrDefault(params.get("limit"), 100);
        
        sendJsonResponse(exchange, programInfoService.listImports(offset, limit));
    }
    
    /**
     * Handle get exports request
     */
    private void handleGetExports(HttpExchange exchange) throws IOException {
        if (!isGetRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        Map<String, String> params = parseQueryParams(exchange);
        int offset = parseIntOrDefault(params.get("offset"), 0);
        int limit = parseIntOrDefault(params.get("limit"), 100);
        
        sendJsonResponse(exchange, programInfoService.listExports(offset, limit));
    }
    
    /**
     * Handle get namespaces request
     */
    private void handleGetNamespaces(HttpExchange exchange) throws IOException {
        if (!isGetRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        Map<String, String> params = parseQueryParams(exchange);
        int offset = parseIntOrDefault(params.get("offset"), 0);
        int limit = parseIntOrDefault(params.get("limit"), 100);
        
        sendJsonResponse(exchange, programInfoService.listNamespaces(offset, limit));
    }
    
    /**
     * Handle get classes request
     */
    private void handleGetClasses(HttpExchange exchange) throws IOException {
        if (!isGetRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        Map<String, String> params = parseQueryParams(exchange);
        int offset = parseIntOrDefault(params.get("offset"), 0);
        int limit = parseIntOrDefault(params.get("limit"), 100);
        
        sendJsonResponse(exchange, programInfoService.getAllClassNames(offset, limit));
    }
    
    /**
     * Handle get data items request
     */
    private void handleGetData(HttpExchange exchange) throws IOException {
        if (!isGetRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        Map<String, String> params = parseQueryParams(exchange);
        int offset = parseIntOrDefault(params.get("offset"), 0);
        int limit = parseIntOrDefault(params.get("limit"), 100);
        
        sendJsonResponse(exchange, programInfoService.listDefinedData(offset, limit));
    }
    
    /**
     * Handle search functions request
     */
    private void handleSearchFunctions(HttpExchange exchange) throws IOException {
        if (!isGetRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        Map<String, String> params = parseQueryParams(exchange);
        String searchTerm = params.get("query");
        
        if (searchTerm == null || searchTerm.isEmpty()) {
            sendErrorResponse(exchange, "Search term is required");
            return;
        }
        
        int offset = parseIntOrDefault(params.get("offset"), 0);
        int limit = parseIntOrDefault(params.get("limit"), 100);
        
        sendJsonResponse(exchange, programInfoService.searchFunctionsByName(searchTerm, offset, limit));
    }
    
    /**
     * Handle get symbol statistics request
     */
    private void handleGetSymbolStats(HttpExchange exchange) throws IOException {
        if (!isGetRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        Map<String, String> params = parseQueryParams(exchange);
        String continuationToken = params.get("continuationToken");
        int limit = parseIntOrDefault(params.get("limit"), 5000);
        String symbolType = params.get("symbolType"); // Optional filter
        
        sendJsonResponse(exchange, programInfoService.getSymbolStats(continuationToken, limit, symbolType));
    }
    
    /**
     * Handle get data type statistics request
     */
    private void handleGetDataTypeStats(HttpExchange exchange) throws IOException {
        if (!isGetRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        Map<String, String> params = parseQueryParams(exchange);
        String continuationToken = params.get("continuationToken");
        int limit = parseIntOrDefault(params.get("limit"), 5000);
        
        sendJsonResponse(exchange, programInfoService.getDataTypeStats(continuationToken, limit));
    }
    
    /**
     * Get or create the ProgramInfoService instance
     * 
     * @return The ProgramInfoService instance
     */
    private ProgramInfoService getOrCreateProgramInfoService() {
        ProgramInfoService service = getService(ProgramInfoService.SERVICE_NAME, ProgramInfoService.class);
        if (service == null) {
            service = new ProgramInfoService();
            // Register the service with the service registry
            plugin.getServiceRegistry().registerService(service);
        }
        return service;
    }
}