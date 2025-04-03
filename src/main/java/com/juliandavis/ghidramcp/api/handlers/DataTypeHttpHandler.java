package com.juliandavis.ghidramcp.api.handlers;

import com.juliandavis.ghidramcp.analysis.data.DataTypeService;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import ghidra.util.Msg;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * HTTP handler for data type operations in the GhidraMCP plugin.
 * <p>
 * This handler exposes endpoints for creating, managing, and applying data types.
 */
public class DataTypeHttpHandler extends BaseHttpHandler {
    
    private static final String CONTENT_TYPE_JSON = "application/json";
    private final DataTypeService dataTypeService;
    
    /**
     * Create a new DataTypeHttpHandler.
     * 
     * @param plugin the GhidraMCPPlugin instance
     */
    public DataTypeHttpHandler(GhidraMCPPlugin plugin) {
        super(plugin);
        
        // Get or create the DataTypeService
        dataTypeService = getOrCreateDataTypeService();
    }
    
    private DataTypeService getOrCreateDataTypeService() {
        // Try to get the existing service
        DataTypeService service = ServiceRegistry.getInstance().getService(
                "DataTypeService", DataTypeService.class);
        
        // If it doesn't exist, create and register it
        if (service == null) {
            service = new DataTypeService();
            ServiceRegistry.getInstance().registerService(service);
        }
        
        return service;
    }
    
    @Override
    public void registerEndpoints() {
        HttpServer server = getPlugin().getServer();
        if (server == null) {
            Msg.error(this, "Cannot register endpoints: server is null");
            return;
        }
        
        // Register DataType endpoints
        server.createContext("/dataTypes/search", this::handleSearchDataTypes);
        server.createContext("/dataTypes/category", this::handleGetDataTypeCategory);
        server.createContext("/dataTypes/createPrimitive", this::handleCreatePrimitiveDataType);
        server.createContext("/dataTypes/createString", this::handleCreateStringDataType);
        server.createContext("/dataTypes/createArray", this::handleCreateArrayDataType);
        server.createContext("/dataTypes/createStructure", this::handleCreateStructureDataType);
        server.createContext("/dataTypes/addFieldToStructure", this::handleAddFieldToStructure);
        server.createContext("/dataTypes/applyStructure", this::handleApplyStructureToMemory);
        server.createContext("/dataTypes/createEnum", this::handleCreateEnumDataType);
        server.createContext("/dataTypes/applyEnum", this::handleApplyEnumToMemory);
        server.createContext("/dataTypes/delete", this::handleDeleteDataType);
        
        Msg.info(this, "Registered DataType endpoints");
    }
    
    /**
     * Handle search data types request.
     */
    private void handleSearchDataTypes(HttpExchange exchange) throws IOException {
        if (!isGetRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        Map<String, String> queryParams = parseQueryParams(exchange);
        String searchPattern = queryParams.get("query");
        String categoryPath = queryParams.get("category");
        int offset = parseIntOrDefault(queryParams.get("offset"), 0);
        int limit = parseIntOrDefault(queryParams.get("limit"), 100);
        
        Map<String, Object> result = dataTypeService.searchDataTypes(searchPattern, categoryPath, offset, limit);
        sendJsonResponse(exchange, result);
    }
    
    /**
     * Handle get data type category request.
     */
    private void handleGetDataTypeCategory(HttpExchange exchange) throws IOException {
        if (!isGetRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        Map<String, String> queryParams = parseQueryParams(exchange);
        String categoryPath = queryParams.get("path");
        
        Map<String, Object> result = dataTypeService.getDataTypeCategory(categoryPath);
        sendJsonResponse(exchange, result);
    }
    
    /**
     * Handle create primitive data type request.
     */
    private void handleCreatePrimitiveDataType(HttpExchange exchange) throws IOException {
        if (!isPostRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        Map<String, String> params = parsePostParams(exchange);
        String dataTypeName = params.get("dataType");
        String address = params.get("address");
        
        // Validate required parameters
        if (dataTypeName == null || address == null) {
            sendErrorResponse(exchange, "Missing required parameters: dataType and address");
            return;
        }
        
        Map<String, Object> result = dataTypeService.createPrimitiveDataType(dataTypeName, address);
        sendJsonResponse(exchange, result);
    }
    
    /**
     * Handle create string data type request.
     */
    private void handleCreateStringDataType(HttpExchange exchange) throws IOException {
        if (!isPostRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        Map<String, String> params = parsePostParams(exchange);
        String stringType = params.get("stringType");
        String address = params.get("address");
        int length = parseIntOrDefault(params.get("length"), -1);
        
        // Validate required parameters
        if (stringType == null || address == null) {
            sendErrorResponse(exchange, "Missing required parameters: stringType and address");
            return;
        }
        
        Map<String, Object> result = dataTypeService.createStringDataType(stringType, address, length);
        sendJsonResponse(exchange, result);
    }
    
    /**
     * Handle create array data type request.
     */
    private void handleCreateArrayDataType(HttpExchange exchange) throws IOException {
        if (!isPostRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        Map<String, String> params = parsePostParams(exchange);
        String elementType = params.get("elementType");
        String address = params.get("address");
        int numElements = parseIntOrDefault(params.get("numElements"), 1);
        
        // Validate required parameters
        if (elementType == null || address == null) {
            sendErrorResponse(exchange, "Missing required parameters: elementType and address");
            return;
        }
        
        Map<String, Object> result = dataTypeService.createArrayDataType(elementType, address, numElements);
        sendJsonResponse(exchange, result);
    }
    
    /**
     * Handle create structure data type request.
     */
    private void handleCreateStructureDataType(HttpExchange exchange) throws IOException {
        if (!isPostRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        Map<String, String> params = parsePostParams(exchange);
        String name = params.get("name");
        String description = params.get("description");
        boolean packed = Boolean.parseBoolean(params.getOrDefault("packed", "false"));
        int alignment = parseIntOrDefault(params.get("alignment"), 0);
        
        // Validate required parameters
        if (name == null) {
            sendErrorResponse(exchange, "Missing required parameter: name");
            return;
        }
        
        Map<String, Object> result = dataTypeService.createStructureDataType(name, description, packed, alignment);
        sendJsonResponse(exchange, result);
    }
    
    /**
     * Handle add field to structure request.
     */
    private void handleAddFieldToStructure(HttpExchange exchange) throws IOException {
        if (!isPostRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        Map<String, String> params = parsePostParams(exchange);
        String structureName = params.get("structureName");
        String fieldName = params.get("fieldName");
        String fieldType = params.get("fieldType");
        String comment = params.get("comment");
        
        // Validate required parameters
        if (structureName == null || fieldName == null || fieldType == null) {
            sendErrorResponse(exchange, "Missing required parameters: structureName, fieldName, fieldType");
            return;
        }
        
        // Get offset parameter if provided, otherwise -1 indicates "append to end"
        int offset = -1;
        if (params.containsKey("offset")) {
            try {
                offset = Integer.parseInt(params.get("offset"));
            } catch (NumberFormatException e) {
                sendErrorResponse(exchange, "Invalid offset value: " + params.get("offset"));
                return;
            }
        }
        
        // If offset is not specified, find the structure and append to the end
        Map<String, Object> result;
        if (offset >= 0) {
            // Use specified offset
            result = dataTypeService.addFieldToStructure(structureName, fieldName, fieldType, comment, offset);
        } else {
            // Find the structure to calculate its length (append to end)
            ghidra.program.model.data.DataType structureType = dataTypeService.findDataType(structureName);
            if (structureType instanceof ghidra.program.model.data.Structure) {
                ghidra.program.model.data.Structure structure = (ghidra.program.model.data.Structure) structureType;
                int appendOffset = structure.getLength();
                result = dataTypeService.addFieldToStructure(structureName, fieldName, fieldType, comment, appendOffset);
            } else {
                // Structure not found or not a structure - pass offset 0 and let error handling in service handle it
                result = dataTypeService.addFieldToStructure(structureName, fieldName, fieldType, comment, 0);
            }
        }
        
        sendJsonResponse(exchange, result);
    }
    
    /**
     * Handle apply structure to memory request.
     */
    private void handleApplyStructureToMemory(HttpExchange exchange) throws IOException {
        if (!isPostRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        Map<String, String> params = parsePostParams(exchange);
        String structureName = params.get("structureName");
        String address = params.get("address");
        
        // Validate required parameters
        if (structureName == null || address == null) {
            sendErrorResponse(exchange, "Missing required parameters: structureName, address");
            return;
        }
        
        Map<String, Object> result = dataTypeService.applyStructureToMemory(structureName, address);
        sendJsonResponse(exchange, result);
    }
    
    /**
     * Handle create enum data type request.
     */
    private void handleCreateEnumDataType(HttpExchange exchange) throws IOException {
        if (!isPostRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        Map<String, String> params = parsePostParams(exchange);
        String name = params.get("name");
        int valueSize = parseIntOrDefault(params.get("valueSize"), 4);
        String description = params.get("description");
        
        // Validate required parameters
        if (name == null) {
            sendErrorResponse(exchange, "Missing required parameter: name");
            return;
        }
        
        // Parse values map from comma-separated name:value pairs
        Map<String, Long> values = new HashMap<>();
        String valuesStr = params.get("values");
        if (valuesStr != null && !valuesStr.isEmpty()) {
            for (String pair : valuesStr.split(",")) {
                String[] parts = pair.split(":");
                if (parts.length == 2) {
                    try {
                        values.put(parts[0].trim(), Long.parseLong(parts[1].trim()));
                    } catch (NumberFormatException e) {
                        sendErrorResponse(exchange, "Invalid enum value: " + pair);
                        return;
                    }
                }
            }
        }
        
        Map<String, Object> result = dataTypeService.createEnumDataType(name, valueSize, values, description);
        sendJsonResponse(exchange, result);
    }
    
    /**
     * Handle apply enum to memory request.
     */
    private void handleApplyEnumToMemory(HttpExchange exchange) throws IOException {
        if (!isPostRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        Map<String, String> params = parsePostParams(exchange);
        String enumName = params.get("enumName");
        String address = params.get("address");
        
        // Validate required parameters
        if (enumName == null || address == null) {
            sendErrorResponse(exchange, "Missing required parameters: enumName, address");
            return;
        }
        
        Map<String, Object> result = dataTypeService.applyEnumToMemory(enumName, address);
        sendJsonResponse(exchange, result);
    }
    
    /**
     * Handle delete data type request.
     */
    private void handleDeleteDataType(HttpExchange exchange) throws IOException {
        if (!isPostRequest(exchange)) {
            sendMethodNotAllowedResponse(exchange);
            return;
        }
        
        Map<String, String> params = parsePostParams(exchange);
        String name = params.get("name");
        
        // Validate required parameters
        if (name == null) {
            sendErrorResponse(exchange, "Missing required parameter: name");
            return;
        }
        
        Map<String, Object> result = dataTypeService.deleteDataType(name);
        sendJsonResponse(exchange, result);
    }
    
    /**
     * Send a JSON response.
     * 
     * @param exchange the HTTP exchange
     * @param data the data to send as JSON
     * @throws IOException if an I/O error occurs
     */
    private void sendJsonResponse(HttpExchange exchange, Map<String, Object> data) throws IOException {
        byte[] responseBytes = getPlugin().getGson().toJson(data).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", CONTENT_TYPE_JSON);
        exchange.sendResponseHeaders(200, responseBytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }
    
    /**
     * Send an error response.
     * 
     * @param exchange the HTTP exchange
     * @param message the error message
     * @throws IOException if an I/O error occurs
     */
    private void sendErrorResponse(HttpExchange exchange, String message) throws IOException {
        Map<String, Object> error = new HashMap<>();
        error.put("success", false);
        error.put("error", message);
        
        byte[] responseBytes = getPlugin().getGson().toJson(error).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", CONTENT_TYPE_JSON);
        exchange.sendResponseHeaders(400, responseBytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }
    
    /**
     * Send a method not allowed response.
     * 
     * @param exchange the HTTP exchange
     * @throws IOException if an I/O error occurs
     */
    private void sendMethodNotAllowedResponse(HttpExchange exchange) throws IOException {
        Map<String, Object> error = new HashMap<>();
        error.put("success", false);
        error.put("error", "Method not allowed");
        
        byte[] responseBytes = getPlugin().getGson().toJson(error).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", CONTENT_TYPE_JSON);
        exchange.sendResponseHeaders(405, responseBytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }
    
    /**
     * Check if the request is a GET request.
     * 
     * @param exchange the HTTP exchange
     * @return true if the request is a GET request, false otherwise
     */
    private boolean isGetRequest(HttpExchange exchange) {
        return "GET".equals(exchange.getRequestMethod());
    }
    
    /**
     * Check if the request is a POST request.
     * 
     * @param exchange the HTTP exchange
     * @return true if the request is a POST request, false otherwise
     */
    private boolean isPostRequest(HttpExchange exchange) {
        return "POST".equals(exchange.getRequestMethod());
    }
    
    /**
     * Parse query parameters from the exchange.
     * 
     * @param exchange the HTTP exchange
     * @return a map of query parameters
     */
    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> queryParams = new HashMap<>();
        String query = exchange.getRequestURI().getQuery();
        
        if (query != null && !query.isEmpty()) {
            for (String param : query.split("&")) {
                String[] pair = param.split("=");
                if (pair.length > 1) {
                    queryParams.put(pair[0], pair[1]);
                } else {
                    queryParams.put(pair[0], "");
                }
            }
        }
        
        return queryParams;
    }
    
    /**
     * Parse POST parameters from the exchange.
     * 
     * @param exchange the HTTP exchange
     * @return a map of POST parameters
     * @throws IOException if an I/O error occurs
     */
    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        String requestBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        Map<String, String> postParams = new HashMap<>();
        
        if (requestBody != null && !requestBody.isEmpty()) {
            for (String param : requestBody.split("&")) {
                String[] pair = param.split("=");
                if (pair.length > 1) {
                    postParams.put(pair[0], pair[1]);
                } else {
                    postParams.put(pair[0], "");
                }
            }
        }
        
        return postParams;
    }
    
    /**
     * Parse an integer from a string with a default value.
     * 
     * @param value the string to parse
     * @param defaultValue the default value to use if parsing fails
     * @return the parsed integer or the default value
     */
    private int parseIntOrDefault(String value, int defaultValue) {
        if (value == null) {
            return defaultValue;
        }
        
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }
}
