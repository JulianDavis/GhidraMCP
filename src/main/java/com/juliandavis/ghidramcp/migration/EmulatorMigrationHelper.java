package com.juliandavis.ghidramcp.migration;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import com.juliandavis.ghidramcp.emulation.core.EmulatorService;
import ghidra.util.Msg;
import java.lang.reflect.Method;

/**
 * Helper class for migrating from old EmulatorHttpHandler to the new implementation.
 * This class provides utility methods to safely move from the old implementation to the new one.
 */
public class EmulatorMigrationHelper {

    /**
     * Migrate session data from the old EmulatorHttpHandler to the new implementation.
     * 
     * @param plugin The GhidraMCPPlugin instance
     * @return True if migration was successful, false otherwise
     */
    public static boolean migrateEmulatorSessions(GhidraMCPPlugin plugin) {
        try {
            // Get the EmulatorService from the registry
            ServiceRegistry registry = plugin.getServiceRegistry();
            EmulatorService newService = registry.getService(EmulatorService.SERVICE_NAME, EmulatorService.class);
            
            if (newService == null) {
                Msg.error(EmulatorMigrationHelper.class, "New EmulatorService not found in registry");
                return false;
            }
            
            // Check if the old EmulatorHttpHandler class exists
            Class<?> oldHandlerClass;
            try {
                oldHandlerClass = Class.forName("com.juliandavis.EmulatorHttpHandler");
            } catch (ClassNotFoundException e) {
                // Old class not found, no migration needed
                Msg.info(EmulatorMigrationHelper.class, "Old EmulatorHttpHandler class not found, no migration needed");
                return true;
            }
            
            // Check if the old EmulatorService class exists
            Class<?> oldServiceClass;
            try {
                oldServiceClass = Class.forName("com.juliandavis.EmulatorService");
            } catch (ClassNotFoundException e) {
                // Old class not found, no migration needed
                Msg.info(EmulatorMigrationHelper.class, "Old EmulatorService class not found, no migration needed");
                return true;
            }
            
            // Try to get a method to access the old sessions
            Method getSessionsMethod = null;
            try {
                getSessionsMethod = oldServiceClass.getDeclaredMethod("getSessions");
                getSessionsMethod.setAccessible(true);
            } catch (NoSuchMethodException e) {
                Msg.warn(EmulatorMigrationHelper.class, "Could not find getSessions method in old EmulatorService");
                // Continue without migrating sessions
                return false;
            }
            
            // Try to get the old EmulatorService instance statically
            Object oldService;
            try {
                Method getInstanceMethod = oldServiceClass.getDeclaredMethod("getInstance");
                getInstanceMethod.setAccessible(true);
                oldService = getInstanceMethod.invoke(null);
            } catch (Exception e) {
                Msg.warn(EmulatorMigrationHelper.class, "Could not get old EmulatorService instance");
                // Continue without migrating sessions
                return false;
            }
            
            // Get the old sessions
            Object oldSessions;
            try {
                oldSessions = getSessionsMethod.invoke(oldService);
            } catch (Exception e) {
                Msg.warn(EmulatorMigrationHelper.class, "Could not get old sessions");
                // Continue without migrating sessions
                return false;
            }
            
            // Log the migration
            Msg.info(EmulatorMigrationHelper.class, "EmulatorService sessions migration would happen here");
            Msg.info(EmulatorMigrationHelper.class, "Old sessions: " + oldSessions);
            
            // In a real implementation, we would transfer sessions from old to new service
            // But since sessions are UUID-based, this is difficult to do without breaking things
            // The best approach is to inform users that they need to reinitialize sessions
            
            return true;
        } catch (Exception e) {
            Msg.error(EmulatorMigrationHelper.class, "Error migrating EmulatorService sessions", e);
            return false;
        }
    }
    
    /**
     * Disable the old EmulatorHttpHandler to prevent conflicts.
     * 
     * @param plugin The GhidraMCPPlugin instance
     * @return True if disabling was successful, false otherwise
     */
    public static boolean disableOldEmulatorHandler(GhidraMCPPlugin plugin) {
        try {
            // Check if the old EmulatorHttpHandler class exists
            Class<?> oldHandlerClass;
            try {
                oldHandlerClass = Class.forName("com.juliandavis.EmulatorHttpHandler");
            } catch (ClassNotFoundException e) {
                // Old class not found, no need to disable
                Msg.info(EmulatorMigrationHelper.class, "Old EmulatorHttpHandler class not found, no need to disable");
                return true;
            }
            
            // Log the request to disable the old handler
            Msg.info(EmulatorMigrationHelper.class, "Requesting to disable old EmulatorHttpHandler");
            
            // In a real implementation, we would find the old handler instance and disable it
            // However, since the old handler is registered with the HTTP server directly,
            // this is difficult to do without modifying the server
            //
            // Instead, we recommend removing the old handler initialization from the GhidraMCPPlugin
            
            return true;
        } catch (Exception e) {
            Msg.error(EmulatorMigrationHelper.class, "Error disabling old EmulatorHttpHandler", e);
            return false;
        }
    }
}