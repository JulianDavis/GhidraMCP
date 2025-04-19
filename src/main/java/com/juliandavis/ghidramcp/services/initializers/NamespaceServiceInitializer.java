package com.juliandavis.ghidramcp.services.initializers;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.api.handlers.NamespaceHttpHandler;
import com.juliandavis.ghidramcp.api.server.EndpointRegistry;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import com.juliandavis.ghidramcp.core.service.initializer.ServiceInitializer;
import com.juliandavis.ghidramcp.services.NamespaceService;
import ghidra.util.Msg;

/**
 * Initializer for the NamespaceService.
 * <p>
 * This class is responsible for registering the NamespaceService with the service registry
 * and for registering the corresponding HTTP handler with the endpoint registry.
 */
public class NamespaceServiceInitializer implements ServiceInitializer {

    private final GhidraMCPPlugin plugin;
    private final ServiceRegistry serviceRegistry;
    private final EndpointRegistry endpointRegistry;

    /**
     * Create a new NamespaceServiceInitializer.
     *
     * @param plugin the GhidraMCPPlugin instance
     * @param serviceRegistry the service registry
     * @param endpointRegistry the endpoint registry
     */
    public NamespaceServiceInitializer(
            GhidraMCPPlugin plugin,
            ServiceRegistry serviceRegistry,
            EndpointRegistry endpointRegistry) {
        this.plugin = plugin;
        this.serviceRegistry = serviceRegistry;
        this.endpointRegistry = endpointRegistry;
    }

    @Override
    public boolean initialize() {
        try {
            // 1. Create the service instance
            NamespaceService namespaceService = new NamespaceService(plugin.getTool());

            // 2. Register the service
            serviceRegistry.registerService(namespaceService);
            Msg.info(this, "Registered service: " + NamespaceService.SERVICE_NAME);

            // 3. Create the HTTP handler instance
            NamespaceHttpHandler namespaceHttpHandler = new NamespaceHttpHandler(plugin);

            // 4. Register the handler's endpoints
            endpointRegistry.registerHandler(namespaceHttpHandler);
            Msg.info(this, "Registered handler for: " + NamespaceService.SERVICE_NAME);

            return true;
        } catch (Exception e) {
            Msg.error(this, "Failed to initialize NamespaceService and its handler", e);
            return false;
        }
    }
}
