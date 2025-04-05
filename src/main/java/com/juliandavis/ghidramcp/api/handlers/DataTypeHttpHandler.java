package com.juliandavis.ghidramcp.api.handlers;

import com.juliandavis.ghidramcp.services.DataTypeService;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import ghidra.util.Msg;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * HTTP handler for data type operations in the GhidraMCP plugin.
 * <p>
 * This handler exposes endpoints for creating, managing, and applying data types.
 */
public class DataTypeHttpHandler extends BaseHttpHandler {
    
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
        HttpServer server = getServer();
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
            if (structureType instanceof ghidra.program.model.data.Structure structure) {
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
    
    // These methods are now provided by BaseHttpHandler, so we don't need to reimplement them
}
