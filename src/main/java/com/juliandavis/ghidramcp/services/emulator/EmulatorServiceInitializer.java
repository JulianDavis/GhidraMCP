package com.juliandavis.ghidramcp.services.emulator;

import com.juliandavis.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.services.ServiceRegistry;
import ghidra.util.Msg;

/**
 * Initializer class for the EmulatorService and related components.
 * Responsible for registering the service and handler with the appropriate registries.
 */
public class EmulatorServiceInitializer {
    
    /**
     * Initialize the EmulatorService and related components.
     * 
     * @param plugin The GhidraMCPPlugin instance
     */
    public static void initialize(GhidraMCPPlugin plugin) {
        // Create and register the EmulatorService
        EmulatorService emulatorService = new EmulatorService();
        ServiceRegistry.getInstance().registerService(emulatorService);
        
        // Set the static instance for backward compatibility
        EmulatorService.setInstance(emulatorService);
        
        // Create and register the EmulatorHttpHandler
        EmulatorHttpHandler emulatorHttpHandler = new EmulatorHttpHandler(plugin);
        plugin.registerHttpHandler(emulatorHttpHandler);
        
        Msg.info(EmulatorServiceInitializer.class, "EmulatorService initialized");
    }
}
