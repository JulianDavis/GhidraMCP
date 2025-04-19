package com.juliandavis.ghidramcp.api.handlers;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.services.MemoryReadService;

import java.util.Map;

/**
 * HTTP handler for direct memory-related endpoints in the GhidraMCP plugin.
 * Provides endpoints for reading memory and getting memory information without requiring an emulator.
 */
public class MemoryReadHttpHandler extends BaseHttpHandler {

    // Service instance will be retrieved from the registry on demand in handler methods
    // private final MemoryReadService memoryReadService; // Removed final field

    /**
     * Creates a new MemoryReadHttpHandler.
     *
     * @param plugin The GhidraMCPPlugin instance
     */
    public MemoryReadHttpHandler(GhidraMCPPlugin plugin) {
        super(plugin);
        // Constructor no longer initializes the service field
        // this.memoryReadService = getOrCreateMemoryReadService();
    }

    /**
     * Register all endpoints with the HTTP server
     */
    @Override
    public void registerEndpoints() {
        // Read memory
        getServer().createContext("/memory/read", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String address = params.get("address");
            int length = Integer.parseInt(params.getOrDefault("length", "16"));

            // Retrieve service instance
            MemoryReadService service = getService(MemoryReadService.SERVICE_NAME, MemoryReadService.class);
            if (service == null) {
                sendErrorResponse(exchange, MemoryReadService.SERVICE_NAME + " not available.", 503);
                return;
            }
            Map<String, Object> response = service.readMemory(address, length);
            sendJsonResponse(exchange, response);
        });

        // Get memory block info
        getServer().createContext("/memory/blockInfo", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String address = params.get("address");

            // Retrieve service instance
            MemoryReadService service = getService(MemoryReadService.SERVICE_NAME, MemoryReadService.class);
             if (service == null) {
                sendErrorResponse(exchange, MemoryReadService.SERVICE_NAME + " not available.", 503);
                return;
            }
            Map<String, Object> response = service.getMemoryBlockInfo(address);
            sendJsonResponse(exchange, response);
        });

        // List all memory blocks
        getServer().createContext("/memory/listBlocks", exchange -> {
            // Retrieve service instance
            MemoryReadService service = getService(MemoryReadService.SERVICE_NAME, MemoryReadService.class);
             if (service == null) {
                sendErrorResponse(exchange, MemoryReadService.SERVICE_NAME + " not available.", 503);
                return;
            }
            Map<String, Object> response = service.listMemoryBlocks();
            sendJsonResponse(exchange, response);
        });

        // Check if address is valid
        getServer().createContext("/memory/isValid", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String address = params.get("address");

            // Retrieve service instance
            MemoryReadService service = getService(MemoryReadService.SERVICE_NAME, MemoryReadService.class);
             if (service == null) {
                sendErrorResponse(exchange, MemoryReadService.SERVICE_NAME + " not available.", 503);
                return;
            }
            Map<String, Object> response = service.isAddressValid(address);
            sendJsonResponse(exchange, response);
        });

        // Get address spaces
        getServer().createContext("/memory/addressSpaces", exchange -> {
            // Retrieve service instance
            MemoryReadService service = getService(MemoryReadService.SERVICE_NAME, MemoryReadService.class);
             if (service == null) {
                sendErrorResponse(exchange, MemoryReadService.SERVICE_NAME + " not available.", 503);
                return;
            }
            Map<String, Object> response = service.getAddressSpaces();
            sendJsonResponse(exchange, response);
        });
    }

    // Removed getOrCreateMemoryReadService method - service retrieval happens in handlers
}
