package com.juliandavis.ghidramcp.services.initializers;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.services.MemoryPatternSearchService;
import com.juliandavis.ghidramcp.api.handlers.MemoryPatternSearchHttpHandler;
import com.juliandavis.ghidramcp.api.server.EndpointRegistry;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import com.juliandavis.ghidramcp.core.service.initializer.BaseServiceInitializer;

/**
 * Initializer for the MemoryPatternSearchService.
 * Registers the service with the ServiceRegistry and sets up the HTTP handler.
 */
public class MemoryPatternSearchServiceInitializer extends BaseServiceInitializer<MemoryPatternSearchService, MemoryPatternSearchHttpHandler> {

    /**
     * Creates a new MemoryPatternSearchServiceInitializer.
     * 
     * @param plugin The GhidraMCP plugin instance
     * @param serviceRegistry The service registry
     * @param endpointRegistry The endpoint registry
     */
    public MemoryPatternSearchServiceInitializer(GhidraMCPPlugin plugin, ServiceRegistry serviceRegistry, EndpointRegistry endpointRegistry) {
        super(plugin, serviceRegistry, endpointRegistry);
    }
    
    @Override
    protected MemoryPatternSearchService createService() {
        return new MemoryPatternSearchService();
    }
    
    @Override
    protected MemoryPatternSearchHttpHandler createHttpHandler() {
        return new MemoryPatternSearchHttpHandler(plugin);
    }
    
    @Override
    protected String getServiceName() {
        return MemoryPatternSearchService.SERVICE_NAME;
    }
    
    /**
     * Static initialization method for backward compatibility.
     * 
     * @param serviceRegistry The service registry to register with
     * @param endpointRegistry The endpoint registry to register the HTTP handler with
     * @param plugin The GhidraMCPPlugin instance
     */
    public static void initialize(ServiceRegistry serviceRegistry, EndpointRegistry endpointRegistry,
                                GhidraMCPPlugin plugin) {
        MemoryPatternSearchServiceInitializer initializer = new MemoryPatternSearchServiceInitializer(
            plugin, serviceRegistry, endpointRegistry);
        initializer.initialize();
    }
}