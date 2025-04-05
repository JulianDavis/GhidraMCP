package com.juliandavis.ghidramcp.services.initializers;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.api.handlers.DisassembleHttpHandler;
import com.juliandavis.ghidramcp.api.server.EndpointRegistry;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import com.juliandavis.ghidramcp.core.service.initializer.BaseServiceInitializer;
import com.juliandavis.ghidramcp.services.DisassembleService;

/**
 * Initializer for the DisassembleService.
 * <p>
 * This class is responsible for registering the DisassembleService with the service registry
 * and for registering the corresponding HTTP handler with the endpoint registry.
 */
public class DisassembleServiceInitializer extends BaseServiceInitializer<DisassembleService, DisassembleHttpHandler> {
    
    /**
     * Create a new DisassembleServiceInitializer.
     * 
     * @param plugin the GhidraMCPPlugin instance
     * @param serviceRegistry the service registry
     * @param endpointRegistry the endpoint registry
     */
    public DisassembleServiceInitializer(
            GhidraMCPPlugin plugin,
            ServiceRegistry serviceRegistry,
            EndpointRegistry endpointRegistry) {
        super(plugin, serviceRegistry, endpointRegistry);
    }
    
    @Override
    protected DisassembleService createService() {
        return new DisassembleService();
    }
    
    @Override
    protected DisassembleHttpHandler createHttpHandler() {
        return new DisassembleHttpHandler(plugin);
    }
    
    @Override
    protected String getServiceName() {
        return DisassembleService.SERVICE_NAME;
    }
}
