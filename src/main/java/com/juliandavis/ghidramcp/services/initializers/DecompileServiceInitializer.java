package com.juliandavis.ghidramcp.services.initializers;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.api.handlers.DecompileHttpHandler;
import com.juliandavis.ghidramcp.api.server.EndpointRegistry;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import com.juliandavis.ghidramcp.core.service.initializer.BaseServiceInitializer;
import com.juliandavis.ghidramcp.services.DecompileService;

/**
 * Initializer for the DecompileService.
 * <p>
 * This class is responsible for registering the DecompileService with the service registry
 * and for registering the corresponding HTTP handler with the endpoint registry.
 */
public class DecompileServiceInitializer extends BaseServiceInitializer<DecompileService, DecompileHttpHandler> {
    
    /**
     * Create a new DecompileServiceInitializer.
     * 
     * @param plugin the GhidraMCPPlugin instance
     * @param serviceRegistry the service registry
     * @param endpointRegistry the endpoint registry
     */
    public DecompileServiceInitializer(
            GhidraMCPPlugin plugin,
            ServiceRegistry serviceRegistry,
            EndpointRegistry endpointRegistry) {
        super(plugin, serviceRegistry, endpointRegistry);
    }
    
    @Override
    protected DecompileService createService() {
        return new DecompileService();
    }
    
    @Override
    protected DecompileHttpHandler createHttpHandler() {
        return new DecompileHttpHandler(plugin);
    }
    
    @Override
    protected String getServiceName() {
        return DecompileService.SERVICE_NAME;
    }
}
