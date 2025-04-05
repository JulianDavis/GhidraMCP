package com.juliandavis.ghidramcp.services.initializers;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.services.MemoryCrossReferenceService;
import com.juliandavis.ghidramcp.api.handlers.MemoryCrossReferenceHttpHandler;
import com.juliandavis.ghidramcp.api.server.EndpointRegistry;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import com.juliandavis.ghidramcp.core.service.initializer.BaseServiceInitializer;

/**
 * Initializer for the MemoryCrossReferenceService.
 * Registers the service with the ServiceRegistry and sets up the HTTP handler.
 */
public class MemoryCrossReferenceServiceInitializer extends BaseServiceInitializer<MemoryCrossReferenceService, MemoryCrossReferenceHttpHandler> {

    /**
     * Creates a new MemoryCrossReferenceServiceInitializer.
     * 
     * @param plugin The GhidraMCP plugin instance
     * @param serviceRegistry The service registry
     * @param endpointRegistry The endpoint registry
     */
    public MemoryCrossReferenceServiceInitializer(GhidraMCPPlugin plugin, ServiceRegistry serviceRegistry, EndpointRegistry endpointRegistry) {
        super(plugin, serviceRegistry, endpointRegistry);
    }
    
    @Override
    protected MemoryCrossReferenceService createService() {
        return new MemoryCrossReferenceService();
    }
    
    @Override
    protected MemoryCrossReferenceHttpHandler createHttpHandler() {
        return new MemoryCrossReferenceHttpHandler(plugin);
    }
    
    @Override
    protected String getServiceName() {
        return "MemoryCrossReferenceService";
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
        MemoryCrossReferenceServiceInitializer initializer = new MemoryCrossReferenceServiceInitializer(
            plugin, serviceRegistry, endpointRegistry);
        initializer.initialize();
    }
}