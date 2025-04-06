package com.juliandavis.ghidramcp.services.initializers;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.api.handlers.MemoryManipulationHttpHandler;
import com.juliandavis.ghidramcp.api.server.EndpointRegistry;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import com.juliandavis.ghidramcp.core.service.initializer.ServiceInitializer;
import com.juliandavis.ghidramcp.services.MemoryManipulationService;
import ghidra.util.Msg;

public class MemoryManipulationServiceInitializer implements ServiceInitializer {

    private final GhidraMCPPlugin plugin;
    private final ServiceRegistry serviceRegistry;
    private final EndpointRegistry endpointRegistry;

    public MemoryManipulationServiceInitializer(GhidraMCPPlugin plugin, ServiceRegistry serviceRegistry, EndpointRegistry endpointRegistry) {
        this.plugin = plugin;
        this.serviceRegistry = serviceRegistry;
        this.endpointRegistry = endpointRegistry;
    }

    @Override
    public boolean initialize() { // Return boolean
        try {
            // 1. Create the service instance
            MemoryManipulationService memoryManipulationService = new MemoryManipulationService(plugin.getTool()); // Pass PluginTool

            // 2. Register the service
            serviceRegistry.registerService(memoryManipulationService); // Pass only the service object
            Msg.info(this, "Registered service: " + MemoryManipulationService.SERVICE_NAME);

            // 3. Create the HTTP handler instance
            MemoryManipulationHttpHandler memoryManipulationHttpHandler = new MemoryManipulationHttpHandler(plugin); // Pass plugin

            // 4. Register the handler's endpoints
            endpointRegistry.registerHandler(memoryManipulationHttpHandler);
            Msg.info(this, "Registered handler for: " + MemoryManipulationService.SERVICE_NAME);

            return true; // Return true on success
        } catch (Exception e) {
            Msg.error(this, "Failed to initialize MemoryManipulationService and its handler", e);
            return false; // Return false on failure
        }
    }
}
