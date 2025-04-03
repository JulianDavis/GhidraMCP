package com.juliandavis.ghidramcp.analysis.search.initializer;

import com.juliandavis.ghidramcp.analysis.search.StringExtractionService;
import com.juliandavis.ghidramcp.api.handlers.StringExtractionHttpHandler;
import com.juliandavis.ghidramcp.api.server.EndpointRegistry;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;

/**
 * Initializer for the StringExtractionService.
 * Registers the service with the ServiceRegistry and sets up the HTTP handler.
 */
public class StringExtractionServiceInitializer {

    /**
     * Initialize the StringExtractionService and its HTTP handler.
     *
     * @param serviceRegistry The service registry to register with
     * @param endpointRegistry The endpoint registry to register the HTTP handler with
     * @param plugin The GhidraMCPPlugin instance
     */
    public static void initialize(ServiceRegistry serviceRegistry, EndpointRegistry endpointRegistry,
                                com.juliandavis.ghidramcp.GhidraMCPPlugin plugin) {
        // Create and register the service
        StringExtractionService service = new StringExtractionService();
        serviceRegistry.registerService(service);
        
        // Create and register the HTTP handler
        StringExtractionHttpHandler handler = new StringExtractionHttpHandler(plugin);
        endpointRegistry.registerHandler(handler);
    }
}