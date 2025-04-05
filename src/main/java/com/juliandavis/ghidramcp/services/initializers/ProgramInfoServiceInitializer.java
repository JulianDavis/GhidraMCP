package com.juliandavis.ghidramcp.services.initializers;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.services.ProgramInfoService;
import com.juliandavis.ghidramcp.api.handlers.ProgramInfoHttpHandler;
import com.juliandavis.ghidramcp.api.server.EndpointRegistry;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import ghidra.util.Msg;

/**
 * Initializer for the ProgramInfoService.
 * <p>
 * This class is responsible for creating and registering both the service
 * and its corresponding HTTP handler.
 */
public class ProgramInfoServiceInitializer {
    
    private final GhidraMCPPlugin plugin;
    private final ServiceRegistry serviceRegistry;
    private final EndpointRegistry endpointRegistry;
    
    /**
     * Create a new ProgramInfoServiceInitializer.
     *
     * @param plugin           the GhidraMCPPlugin instance
     * @param serviceRegistry  the service registry
     * @param endpointRegistry the endpoint registry
     */
    public ProgramInfoServiceInitializer(
            GhidraMCPPlugin plugin,
            ServiceRegistry serviceRegistry,
            EndpointRegistry endpointRegistry) {
        this.plugin = plugin;
        this.serviceRegistry = serviceRegistry;
        this.endpointRegistry = endpointRegistry;
    }
    
    /**
     * Initialize the service and handler.
     */
    public void initialize() {
        // Create and register the service
        ProgramInfoService service = new ProgramInfoService();
        serviceRegistry.registerService(service);
        
        // Create and register the handler
        ProgramInfoHttpHandler handler = new ProgramInfoHttpHandler(plugin);
        endpointRegistry.registerHandler(handler);
        
        Msg.info(this, "ProgramInfoService initialized");
    }
}
