package com.juliandavis.ghidramcp.services.initializers;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.api.handlers.FunctionXrefHttpHandler;
import com.juliandavis.ghidramcp.api.server.EndpointRegistry;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import com.juliandavis.ghidramcp.core.service.initializer.BaseServiceInitializer;
import com.juliandavis.ghidramcp.services.FunctionXrefService;

/**
 * Initializer for the FunctionXrefService.
 * <p>
 * This class is responsible for registering the FunctionXrefService with the service registry
 * and for registering the corresponding HTTP handler with the endpoint registry.
 */
public class FunctionXrefServiceInitializer extends BaseServiceInitializer<FunctionXrefService, FunctionXrefHttpHandler> {
    
    /**
     * Create a new FunctionXrefServiceInitializer.
     * 
     * @param plugin the GhidraMCPPlugin instance
     * @param serviceRegistry the service registry
     * @param endpointRegistry the endpoint registry
     */
    public FunctionXrefServiceInitializer(
            GhidraMCPPlugin plugin,
            ServiceRegistry serviceRegistry,
            EndpointRegistry endpointRegistry) {
        super(plugin, serviceRegistry, endpointRegistry);
    }
    
    @Override
    protected FunctionXrefService createService() {
        return new FunctionXrefService();
    }
    
    @Override
    protected FunctionXrefHttpHandler createHttpHandler() {
        return new FunctionXrefHttpHandler(plugin);
    }
    
    @Override
    protected String getServiceName() { return FunctionXrefService.SERVICE_NAME; }
}
