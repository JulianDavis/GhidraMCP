package com.juliandavis.ghidramcp.api.handlers;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.services.MemoryReadService;

import java.util.Map;

/**
 * HTTP handler for direct memory-related endpoints in the GhidraMCP plugin.
 * Provides endpoints for reading memory and getting memory information without requiring an emulator.
 */
public class MemoryReadHttpHandler extends BaseHttpHandler {

    private final MemoryReadService memoryReadService;

    /**
     * Creates a new MemoryReadHttpHandler.
     *
     * @param plugin The GhidraMCPPlugin instance
     */
    public MemoryReadHttpHandler(GhidraMCPPlugin plugin) {
        super(plugin);
        this.memoryReadService = getOrCreateMemoryReadService();
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

            Map<String, Object> response = memoryReadService.readMemory(address, length);
            sendJsonResponse(exchange, response);
        });

        // Get memory block info
        getServer().createContext("/memory/blockInfo", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String address = params.get("address");

            Map<String, Object> response = memoryReadService.getMemoryBlockInfo(address);
            sendJsonResponse(exchange, response);
        });

        // List all memory blocks
        getServer().createContext("/memory/listBlocks", exchange -> {
            Map<String, Object> response = memoryReadService.listMemoryBlocks();
            sendJsonResponse(exchange, response);
        });

        // Check if address is valid
        getServer().createContext("/memory/isValid", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String address = params.get("address");

            Map<String, Object> response = memoryReadService.isAddressValid(address);
            sendJsonResponse(exchange, response);
        });

        // Get address spaces
        getServer().createContext("/memory/addressSpaces", exchange -> {
            Map<String, Object> response = memoryReadService.getAddressSpaces();
            sendJsonResponse(exchange, response);
        });
    }

    /**
     * Gets or creates the MemoryReadService instance.
     *
     * @return The MemoryReadService instance
     */
    private MemoryReadService getOrCreateMemoryReadService() {
        MemoryReadService service = getService(MemoryReadService.SERVICE_NAME, MemoryReadService.class);
        if (service == null) {
            service = new MemoryReadService();
            // Register the service with the service registry
            plugin.getServiceRegistry().registerService(service);
        }
        return service;
    }
}