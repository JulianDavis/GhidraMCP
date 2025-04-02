package com.juliandavis.ghidramcp.emulation.initializer;

import com.juliandavis.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.api.handlers.EmulatorHttpHandler;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import com.juliandavis.ghidramcp.emulation.core.EmulatorService;
import ghidra.util.Msg;

/**
 * Initializer for the Emulator components in the GhidraMCP plugin.
 * This class handles the registration of services and HTTP handlers related to emulation.
 */
public class EmulatorServiceInitializer {
    
    private final GhidraMCPPlugin plugin;
    private final ServiceRegistry serviceRegistry;
    private EmulatorService emulatorService;
    private EmulatorHttpHandler emulatorHttpHandler;
    
    /**
     * Creates a new EmulatorServiceInitializer.
     * 
     * @param plugin The GhidraMCP plugin instance
     * @param serviceRegistry The service registry
     */
    public EmulatorServiceInitializer(GhidraMCPPlugin plugin, ServiceRegistry serviceRegistry) {
        this.plugin = plugin;
        this.serviceRegistry = serviceRegistry;
    }
    
    /**
     * Initializes the emulator components.
     * 
     * @return true if initialization succeeded, false otherwise
     */
    public boolean initialize() {
        try {
            // Create and register the emulator service
            emulatorService = new EmulatorService();
            serviceRegistry.registerService(emulatorService);
            
            // Create and register the emulator HTTP handler
            emulatorHttpHandler = new EmulatorHttpHandler(plugin);
            emulatorHttpHandler.registerEndpoints();
            
            Msg.info(this, "Emulator components initialized successfully");
            return true;
        } catch (Exception e) {
            Msg.error(this, "Failed to initialize emulator components", e);
            return false;
        }
    }
    
    /**
     * Disposes of the emulator components.
     */
    public void dispose() {
        // Clean up any resources
        if (emulatorService != null) {
            serviceRegistry.unregisterService(emulatorService.getName());
        }
        
        Msg.info(this, "Emulator components disposed");
    }
}