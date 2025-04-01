package com.juliandavis.ghidramcp;

import java.io.IOException;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.juliandavis.ghidramcp.api.server.HttpServerManager;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import com.juliandavis.ghidramcp.services.datatype.DataTypeServiceInitializer;
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
        // Initialize DataTypeService
        DataTypeServiceInitializer.initialize(this);
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
}
