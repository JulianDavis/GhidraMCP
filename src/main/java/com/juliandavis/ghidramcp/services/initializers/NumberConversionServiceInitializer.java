package com.juliandavis.ghidramcp.services.initializers;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.api.handlers.NumberConversionHttpHandler;
import com.juliandavis.ghidramcp.api.server.EndpointRegistry;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import com.juliandavis.ghidramcp.core.service.initializer.BaseServiceInitializer;
import com.juliandavis.ghidramcp.services.NumberConversionService;

/**
 * Initializer for the NumberConversion components in the GhidraMCP plugin.
 * This class handles the registration of services and HTTP handlers related to number conversion.
 */
public class NumberConversionServiceInitializer extends BaseServiceInitializer<NumberConversionService, NumberConversionHttpHandler> {

    /**
     * Creates a new NumberConversionServiceInitializer.
     *
     * @param plugin The GhidraMCP plugin instance
     * @param serviceRegistry The service registry
     * @param endpointRegistry The endpoint registry
     */
    public NumberConversionServiceInitializer(GhidraMCPPlugin plugin, ServiceRegistry serviceRegistry, EndpointRegistry endpointRegistry) {
        super(plugin, serviceRegistry, endpointRegistry);
    }

    @Override
    protected NumberConversionService createService() {
        return new NumberConversionService();
    }

    @Override
    protected NumberConversionHttpHandler createHttpHandler() {
        return new NumberConversionHttpHandler(plugin);
    }

    @Override
    protected String getServiceName() {
        return NumberConversionService.SERVICE_NAME;
    }
}