package com.juliandavis.ghidramcp.services.initializers;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.api.handlers.MemoryReadHttpHandler;
import com.juliandavis.ghidramcp.api.server.EndpointRegistry;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import com.juliandavis.ghidramcp.core.service.initializer.BaseServiceInitializer;
import com.juliandavis.ghidramcp.services.MemoryReadService;

/**
 * Initializer for the MemoryRead components in the GhidraMCP plugin.
 * This class handles the registration of services and HTTP handlers related to direct memory access.
 */
public class MemoryReadServiceInitializer extends BaseServiceInitializer<MemoryReadService, MemoryReadHttpHandler> {

    /**
     * Creates a new MemoryReadServiceInitializer.
     *
     * @param plugin The GhidraMCP plugin instance
     * @param serviceRegistry The service registry
     * @param endpointRegistry The endpoint registry
     */
    public MemoryReadServiceInitializer(GhidraMCPPlugin plugin, ServiceRegistry serviceRegistry, EndpointRegistry endpointRegistry) {
        super(plugin, serviceRegistry, endpointRegistry);
    }

    @Override
    protected MemoryReadService createService() {
        return new MemoryReadService();
    }

    @Override
    protected MemoryReadHttpHandler createHttpHandler() {
        return new MemoryReadHttpHandler(plugin);
    }

    @Override
    protected String getServiceName() {
        return MemoryReadService.SERVICE_NAME;
    }
}