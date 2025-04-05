package com.juliandavis.ghidramcp.services.initializers;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.services.StringExtractionService;
import com.juliandavis.ghidramcp.api.handlers.StringExtractionHttpHandler;
import com.juliandavis.ghidramcp.api.server.EndpointRegistry;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import com.juliandavis.ghidramcp.core.service.initializer.BaseServiceInitializer;

/**
 * Initializer for the StringExtractionService.
 * Registers the service with the ServiceRegistry and sets up the HTTP handler.
 */
public class StringExtractionServiceInitializer extends BaseServiceInitializer<StringExtractionService, StringExtractionHttpHandler> {

    /**
     * Creates a new StringExtractionServiceInitializer.
     * 
     * @param plugin The GhidraMCP plugin instance
     * @param serviceRegistry The service registry
     * @param endpointRegistry The endpoint registry
     */
    public StringExtractionServiceInitializer(GhidraMCPPlugin plugin, ServiceRegistry serviceRegistry, EndpointRegistry endpointRegistry) {
        super(plugin, serviceRegistry, endpointRegistry);
    }
    
    @Override
    protected StringExtractionService createService() {
        return new StringExtractionService();
    }
    
    @Override
    protected StringExtractionHttpHandler createHttpHandler() {
        return new StringExtractionHttpHandler(plugin);
    }
    
    @Override
    protected String getServiceName() {
        return StringExtractionService.SERVICE_NAME;
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
        StringExtractionServiceInitializer initializer = new StringExtractionServiceInitializer(
            plugin, serviceRegistry, endpointRegistry);
        initializer.initialize();
    }
}