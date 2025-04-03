package com.juliandavis.ghidramcp.core.service.initializer;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.api.handlers.BaseHttpHandler;
import com.juliandavis.ghidramcp.api.server.EndpointRegistry;
import com.juliandavis.ghidramcp.core.service.Service;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import ghidra.util.Msg;

/**
 * Base abstract class for all service initializers.
 * <p>
 * This class provides a standard pattern for initializing services and their HTTP handlers.
 * All service initializers should extend this class to ensure consistency across the codebase.
 */
public abstract class BaseServiceInitializer<S extends Service, H extends BaseHttpHandler> {
    
    protected final GhidraMCPPlugin plugin;
    protected final ServiceRegistry serviceRegistry;
    protected final EndpointRegistry endpointRegistry;
    protected S service;
    protected H httpHandler;
    
    /**
     * Creates a new BaseServiceInitializer.
     * 
     * @param plugin The GhidraMCP plugin instance
     * @param serviceRegistry The service registry
     * @param endpointRegistry The endpoint registry
     */
    public BaseServiceInitializer(GhidraMCPPlugin plugin, ServiceRegistry serviceRegistry, EndpointRegistry endpointRegistry) {
        this.plugin = plugin;
        this.serviceRegistry = serviceRegistry;
        this.endpointRegistry = endpointRegistry;
    }
    
    /**
     * Initializes the service and registers its HTTP handler.
     * 
     * @return true if initialization succeeded, false otherwise
     */
    public boolean initialize() {
        try {
            // Create and register the service
            service = createService();
            serviceRegistry.registerService(service);
            
            // Create and register the HTTP handler
            httpHandler = createHttpHandler();
            endpointRegistry.registerHandler(httpHandler);
            
            Msg.info(this, getServiceName() + " initialized successfully");
            return true;
        } catch (Exception e) {
            Msg.error(this, "Failed to initialize " + getServiceName(), e);
            return false;
        }
    }
    
    /**
     * Creates the service instance.
     * 
     * @return the service instance
     */
    protected abstract S createService();
    
    /**
     * Creates the HTTP handler for the service.
     * 
     * @return the HTTP handler
     */
    protected abstract H createHttpHandler();
    
    /**
     * Gets the service name for logging purposes.
     * 
     * @return the service name
     */
    protected abstract String getServiceName();
    
    /**
     * Disposes of the service components.
     * <p>
     * This method can be overridden by subclasses if additional cleanup is needed.
     * By default, it does nothing as the ServiceRegistry automatically handles service disposal.
     */
    public void dispose() {
        // Default implementation does nothing
        // ServiceRegistry will automatically dispose the service
    }
}