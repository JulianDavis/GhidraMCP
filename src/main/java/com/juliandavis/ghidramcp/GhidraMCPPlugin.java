package com.juliandavis.ghidramcp;

import java.io.IOException;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.juliandavis.ghidramcp.api.server.HttpServerManager;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import com.juliandavis.ghidramcp.services.datatype.DataTypeServiceInitializer;
import com.juliandavis.ghidramcp.emulation.initializer.EmulatorServiceInitializer;
import com.juliandavis.ghidramcp.analysis.memory.initializer.MemoryCrossReferenceServiceInitializer;
import com.juliandavis.ghidramcp.analysis.memory.initializer.MemoryPatternSearchServiceInitializer;
import com.juliandavis.ghidramcp.analysis.search.initializer.StringExtractionServiceInitializer;
import com.juliandavis.ghidramcp.test.EmulatorMigrationVerifier;
import com.juliandavis.ghidramcp.migration.EmulatorMigrationHelper;
import com.sun.net.httpserver.HttpServer;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Main plugin class for the Ghidra Model Context Protocol (GhidraMCP).
 * <p>
 * This plugin starts an HTTP server to expose program data and functionality,
 * allowing external tools to interact with Ghidra.
 */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "GhidraMCP",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data."
)
public class GhidraMCPPlugin extends ProgramPlugin {

    private HttpServerManager serverManager;
    private final Gson gson;
    
    /**
     * Create a new GhidraMCPPlugin instance.
     * 
     * @param tool the Ghidra PluginTool
     */
    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        
        Msg.info(this, "GhidraMCPPlugin loaded!");
        
        // Create JSON serializer
        gson = new GsonBuilder()
                .setPrettyPrinting()
                .create();
        
        // Initialize server manager
        serverManager = new HttpServerManager(this);
        
        // Initialize all services
        initializeServices();
        
        // Verify the emulator migration
        verifyEmulatorMigration();
        
        try {
            // Start HTTP server
            serverManager.startServer();
        } catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
    }
    
    /**
     * Initialize all services used by the plugin.
     */
    private void initializeServices() {
        ServiceRegistry registry = ServiceRegistry.getInstance();
        
        // Initialize DataTypeService
        DataTypeServiceInitializer.initialize(this);
        
        // Initialize EmulatorService
        EmulatorServiceInitializer emulatorInitializer = new EmulatorServiceInitializer(
            this, registry);
        emulatorInitializer.initialize();
        
        // Initialize memory analysis services
        MemoryCrossReferenceServiceInitializer mcrsInitializer = new MemoryCrossReferenceServiceInitializer(
            this, registry);
        mcrsInitializer.initialize();
        
        MemoryPatternSearchServiceInitializer mpssInitializer = new MemoryPatternSearchServiceInitializer(
            this, registry);
        mpssInitializer.initialize();
        
        // Initialize search services
        StringExtractionServiceInitializer sesInitializer = new StringExtractionServiceInitializer(
            this, registry);
        sesInitializer.initialize();
    }
    
    @Override
    public void init() {
        super.init();
        
        // Register for program events
        tool.getService(ProgramManager.class).addProgramChangeListener(this);
    }
    
    @Override
    public void dispose() {
        super.dispose();
        
        // Stop HTTP server
        if (serverManager != null) {
            serverManager.stopServer();
        }
        
        // Dispose all services
        ServiceRegistry.getInstance().disposeAllServices();
    }
    
    @Override
    protected void programActivated(Program program) {
        super.programActivated(program);
        
        // Update services with new program
        ServiceRegistry.getInstance().programChanged(program);
    }
    
    @Override
    protected void programDeactivated(Program program) {
        super.programDeactivated(program);
        
        // Update services with null program
        ServiceRegistry.getInstance().programChanged(null);
    }
    
    /**
     * Get the HTTP server instance.
     * 
     * @return the HTTP server instance
     */
    public HttpServer getServer() {
        return serverManager.getServer();
    }
    
    /**
     * Get the HTTP server manager.
     * 
     * @return the HTTP server manager
     */
    public HttpServerManager getServerManager() {
        return serverManager;
    }
    
    /**
     * Get the Gson instance for JSON serialization/deserialization.
     * 
     * @return the Gson instance
     */
    public Gson getGson() {
        return gson;
    }
    
    /**
     * Get the ServiceRegistry instance.
     * 
     * @return the ServiceRegistry instance
     */
    public ServiceRegistry getServiceRegistry() {
        return ServiceRegistry.getInstance();
    }
    
    /**
     * Verify that the emulator migration has been completed successfully.
     * This method checks for duplicate handlers and verifies endpoint migration.
     */
    private void verifyEmulatorMigration() {
        try {
            // Check for duplicate handlers
            boolean hasDuplicates = EmulatorMigrationVerifier.checkForDuplicateHandlers(this);
            if (hasDuplicates) {
                Msg.warn(this, "WARNING: Duplicate EmulatorHttpHandler implementations detected!");
                Msg.warn(this, "This may cause conflicts in endpoint handling.");
                Msg.warn(this, "Please remove the deprecated implementation in com.juliandavis package.");
                
                // Try to migrate sessions from old to new implementation
                boolean sessionsMigrated = EmulatorMigrationHelper.migrateEmulatorSessions(this);
                if (sessionsMigrated) {
                    Msg.info(this, "Emulator sessions migration completed.");
                } else {
                    Msg.warn(this, "Emulator sessions migration failed or was not necessary.");
                }
                
                // Try to disable the old handler
                boolean oldHandlerDisabled = EmulatorMigrationHelper.disableOldEmulatorHandler(this);
                if (oldHandlerDisabled) {
                    Msg.info(this, "Old EmulatorHttpHandler has been disabled.");
                } else {
                    Msg.warn(this, "Failed to disable old EmulatorHttpHandler.");
                }
            } else {
                Msg.info(this, "No duplicate EmulatorHttpHandler implementations detected.");
            }
            
            // Verify endpoint migration
            boolean endpointsMigrated = EmulatorMigrationVerifier.verifyEndpointMigration(this);
            if (endpointsMigrated) {
                Msg.info(this, "Emulator endpoints migration verified successfully.");
            } else {
                Msg.warn(this, "Some emulator endpoints may not have been migrated correctly.");
                Msg.warn(this, "Please check the EmulatorHttpHandler implementation.");
            }
        } catch (Exception e) {
            Msg.error(this, "Error verifying emulator migration: " + e.getMessage(), e);
        }
    }
}
