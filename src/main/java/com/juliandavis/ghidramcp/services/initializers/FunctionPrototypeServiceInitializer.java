package com.juliandavis.ghidramcp.services.initializers;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.api.handlers.FunctionPrototypeHttpHandler;
import com.juliandavis.ghidramcp.api.server.EndpointRegistry;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import com.juliandavis.ghidramcp.core.service.initializer.BaseServiceInitializer;
import com.juliandavis.ghidramcp.services.FunctionPrototypeService;

/**
 * Initializer for the FunctionPrototypeService.
 * <p>
 * This class is responsible for registering the FunctionPrototypeService with the service registry
 * and for registering the corresponding HTTP handler with the endpoint registry.
 */
public class FunctionPrototypeServiceInitializer extends BaseServiceInitializer<FunctionPrototypeService, FunctionPrototypeHttpHandler> {
    
    /**
     * Create a new FunctionPrototypeServiceInitializer.
     * 
     * @param plugin the GhidraMCPPlugin instance
     * @param serviceRegistry the service registry
     * @param endpointRegistry the endpoint registry
     */
    public FunctionPrototypeServiceInitializer(
            GhidraMCPPlugin plugin,
            ServiceRegistry serviceRegistry,
            EndpointRegistry endpointRegistry) {
        super(plugin, serviceRegistry, endpointRegistry);
    }
    
    @Override
    protected FunctionPrototypeService createService() {
        return new FunctionPrototypeService();
    }
    
    @Override
    protected FunctionPrototypeHttpHandler createHttpHandler() {
        return new FunctionPrototypeHttpHandler(plugin);
    }
    
    @Override
    protected String getServiceName() {
        return FunctionPrototypeService.SERVICE_NAME;
    }
}
