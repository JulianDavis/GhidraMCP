package com.juliandavis.ghidramcp.emulation.initializer;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.api.handlers.EmulatorHttpHandler;
import com.juliandavis.ghidramcp.api.server.EndpointRegistry;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import com.juliandavis.ghidramcp.core.service.initializer.BaseServiceInitializer;
import com.juliandavis.ghidramcp.emulation.core.EmulatorService;

/**
 * Initializer for the Emulator components in the GhidraMCP plugin.
 * This class handles the registration of services and HTTP handlers related to emulation.
 */
public class EmulatorServiceInitializer extends BaseServiceInitializer<EmulatorService, EmulatorHttpHandler> {
    
    /**
     * Creates a new EmulatorServiceInitializer.
     * 
     * @param plugin The GhidraMCP plugin instance
     * @param serviceRegistry The service registry
     * @param endpointRegistry The endpoint registry
     */
    public EmulatorServiceInitializer(GhidraMCPPlugin plugin, ServiceRegistry serviceRegistry, EndpointRegistry endpointRegistry) {
        super(plugin, serviceRegistry, endpointRegistry);
    }
    
    @Override
    protected EmulatorService createService() {
        return new EmulatorService();
    }
    
    @Override
    protected EmulatorHttpHandler createHttpHandler() {
        return new EmulatorHttpHandler(plugin);
    }
    
    @Override
    protected String getServiceName() {
        return "EmulatorService";
    }
}