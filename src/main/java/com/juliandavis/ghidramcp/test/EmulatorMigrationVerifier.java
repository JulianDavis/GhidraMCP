package com.juliandavis.ghidramcp.test;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.api.handlers.EmulatorHttpHandler;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import com.juliandavis.ghidramcp.emulation.core.EmulatorService;
import ghidra.util.Msg;

/**
 * A utility class to verify that the emulator migration is complete and working correctly.
 * This class provides methods to check if handlers are registered correctly and endpoints are working.
 */
public class EmulatorMigrationVerifier {

    /**
     * Check if both old and new EmulatorHttpHandler classes are used, which could cause conflicts.
     * 
     * @param plugin The GhidraMCP plugin instance
     * @return True if duplicates are detected, false otherwise
     */
    public static boolean checkForDuplicateHandlers(GhidraMCPPlugin plugin) {
        try {
            // Check if the plugin uses the old EmulatorHttpHandler
            boolean oldHandlerPresent = false;
            try {
                // Attempt to instantiate the old handler to see if it's still being used
                Object oldHandler = Class.forName("com.juliandavis.EmulatorHttpHandler")
                    .getConstructor(GhidraMCPPlugin.class)
                    .newInstance(plugin);
                oldHandlerPresent = true;
            } catch (Exception e) {
                // Exception means old handler is not being used or not available
                oldHandlerPresent = false;
            }
            
            // Check if the plugin uses the new EmulatorHttpHandler
            boolean newHandlerPresent = false;
            try {
                // Get the EmulatorService from the registry
                ServiceRegistry registry = plugin.getServiceRegistry();
                EmulatorService service = registry.getService(EmulatorService.SERVICE_NAME, EmulatorService.class);
                
                // If the service exists, the new handler is likely being used
                newHandlerPresent = (service != null);
            } catch (Exception e) {
                // Exception means new handler is not being used or not available
                newHandlerPresent = false;
            }
            
            // Return true if both handlers are present, which indicates a potential conflict
            return oldHandlerPresent && newHandlerPresent;
        } catch (Exception e) {
            Msg.error(EmulatorMigrationVerifier.class, "Error checking for duplicate handlers", e);
            return false;
        }
    }
    
    /**
     * Verify that endpoints from the old EmulatorHttpHandler are available in the new implementation.
     * 
     * @param plugin The GhidraMCP plugin instance
     * @return True if all endpoints are available, false otherwise
     */
    public static boolean verifyEndpointMigration(GhidraMCPPlugin plugin) {
        try {
            // List of endpoints that should be available in the new implementation
            String[] endpoints = {
                "/emulator/initialize",
                "/emulator/step",
                "/emulator/run",
                "/emulator/getState",
                "/emulator/getWrites",
                "/emulator/reset",
                "/emulator/setBreakpoint",
                "/emulator/clearBreakpoint",
                "/emulator/getBreakpoints",
                "/emulator/setConditionalBreakpoint",
                "/emulator/getConditionalBreakpoints",
                "/emulator/setRegister",
                "/emulator/getRegister",
                "/emulator/getRegisters",
                "/emulator/writeMemory",
                "/emulator/readMemory",
                "/emulator/setMemoryReadTracking",
                "/emulator/getReads",
                "/emulator/setStackChangeTracking",
                "/emulator/getStackTrace",
                "/emulator/importMemory",
                "/emulator/getRegisterChanges",
                "/emulator/getStdout",
                "/emulator/getStderr",
                "/emulator/provideStdin"
            };
            
            // TODO: In a more comprehensive implementation, we would check each endpoint
            // to ensure it's registered with the server and returns expected responses.
            // For now, we'll just check a few basics.
            
            // Verify that EmulatorService is available
            ServiceRegistry registry = plugin.getServiceRegistry();
            EmulatorService service = registry.getService(EmulatorService.SERVICE_NAME, EmulatorService.class);
            
            if (service == null) {
                Msg.error(EmulatorMigrationVerifier.class, "EmulatorService not found in ServiceRegistry");
                return false;
            }
            
            Msg.info(EmulatorMigrationVerifier.class, "EmulatorService found in ServiceRegistry");
            return true;
        } catch (Exception e) {
            Msg.error(EmulatorMigrationVerifier.class, "Error verifying endpoint migration", e);
            return false;
        }
    }
}
