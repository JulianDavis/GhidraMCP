package com.juliandavis.ghidramcp.analysis.memory.initializer;

import com.juliandavis.ghidramcp.analysis.memory.MemoryPatternSearchService;
import com.juliandavis.ghidramcp.api.handlers.MemoryPatternSearchHttpHandler;
import com.juliandavis.ghidramcp.api.server.EndpointRegistry;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;

/**
 * Initializer for the MemoryPatternSearchService.
 * Registers the service with the ServiceRegistry and sets up the HTTP handler.
 */
public class MemoryPatternSearchServiceInitializer {

    /**
     * Initialize the MemoryPatternSearchService and its HTTP handler.
     *
     * @param serviceRegistry The service registry to register with
     * @param endpointRegistry The endpoint registry to register the HTTP handler with
     * @param plugin The GhidraMCPPlugin instance
     */
    public static void initialize(ServiceRegistry serviceRegistry, EndpointRegistry endpointRegistry,
                                com.juliandavis.ghidramcp.GhidraMCPPlugin plugin) {
        // Create and register the service
        MemoryPatternSearchService service = new MemoryPatternSearchService();
        serviceRegistry.registerService(service);
        
        // Create and register the HTTP handler
        MemoryPatternSearchHttpHandler handler = new MemoryPatternSearchHttpHandler(plugin);
        endpointRegistry.registerHandler(handler);
    }
}