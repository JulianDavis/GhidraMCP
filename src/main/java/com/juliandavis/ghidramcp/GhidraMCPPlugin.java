package com.juliandavis.ghidramcp;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import com.juliandavis.ghidramcp.api.server.EndpointRegistry;
import com.juliandavis.ghidramcp.api.server.HttpServerManager;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import com.juliandavis.ghidramcp.emulation.initializer.EmulatorServiceInitializer;
import com.juliandavis.ghidramcp.analysis.data.initializer.DataTypeServiceInitializer;
import com.juliandavis.ghidramcp.analysis.memory.initializer.MemoryCrossReferenceServiceInitializer;
import com.juliandavis.ghidramcp.analysis.memory.initializer.MemoryPatternSearchServiceInitializer;
import com.juliandavis.ghidramcp.analysis.search.initializer.StringExtractionServiceInitializer;

/**
 * GhidraMCP (Model Context Protocol) Plugin
 * <p>
 * This plugin provides an HTTP API to expose Ghidra's functionality to external tools.
 * It uses a service-oriented architecture to organize functionality into modular components.
 */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Ghidra Model Context Protocol",
    description = "Provides an HTTP API to interact with Ghidra programmatically."
)
public class GhidraMCPPlugin extends ProgramPlugin {

    private ServiceRegistry serviceRegistry;
    private HttpServerManager serverManager;
    private EndpointRegistry endpointRegistry;

    /**
     * Plugin constructor.
     *
     * @param tool The plugin tool this plugin is added to
     */
    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCP Plugin initializing...");
        
        // Initialize core infrastructure
        initializeInfrastructure();
        
        // Initialize and register all services
        registerServices();
        
        // Start the HTTP server
        startServer();
        
        Msg.info(this, "GhidraMCP Plugin initialized successfully");
    }
    
    private void initializeInfrastructure() {
        // Create service registry (using singleton instance)
        serviceRegistry = ServiceRegistry.getInstance();
        
        // Create endpoint registry with reference to this plugin
        endpointRegistry = new EndpointRegistry(this);
        
        // Create HTTP server manager with reference to this plugin
        serverManager = new HttpServerManager(this);
    }
    
    private void registerServices() {
        // Initialize all services through their initializers
        // Each initializer registers the service and its HTTP handlers
        
        // Data services
        DataTypeServiceInitializer dataTypeInitializer = new DataTypeServiceInitializer(this, serviceRegistry, endpointRegistry);
        dataTypeInitializer.initialize();
        
        // Emulation services
        EmulatorServiceInitializer emulatorInitializer = new EmulatorServiceInitializer(this, serviceRegistry, endpointRegistry);
        emulatorInitializer.initialize();
        
        // Memory analysis services
        MemoryCrossReferenceServiceInitializer memXrefInitializer = new MemoryCrossReferenceServiceInitializer(this, serviceRegistry, endpointRegistry);
        memXrefInitializer.initialize();
        
        MemoryPatternSearchServiceInitializer memPatternInitializer = new MemoryPatternSearchServiceInitializer(this, serviceRegistry, endpointRegistry);
        memPatternInitializer.initialize();
        
        // Search services
        StringExtractionServiceInitializer stringExtractionInitializer = new StringExtractionServiceInitializer(this, serviceRegistry, endpointRegistry);
        stringExtractionInitializer.initialize();
        
        // TODO: Add ProgramInfoService initializer once implemented
    }
    
    private void startServer() {
        try {
            serverManager.startServer();
        }
        catch (Exception e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
    }
    
    @Override
    protected void programActivated(Program program) {
        // Notify the service registry of the program change
        serviceRegistry.programChanged(program);
    }
    
    @Override
    protected void programDeactivated(Program program) {
        // Notify the service registry of the program change
        serviceRegistry.programChanged(null);
    }
    
    @Override
    protected void dispose() {
        // Stop the HTTP server
        serverManager.stopServer();
        
        // Dispose all services through the service registry
        // This will call dispose() on each service
        serviceRegistry.disposeAllServices();
        
        super.dispose();
        
        Msg.info(this, "GhidraMCP Plugin disposed");
    }
    
    /**
     * Get the service registry
     * 
     * @return The service registry
     */
    public ServiceRegistry getServiceRegistry() {
        return serviceRegistry;
    }
    
    /**
     * Get the HTTP server manager
     * 
     * @return The HTTP server manager
     */
    public HttpServerManager getServerManager() {
        return serverManager;
    }
    
    /**
     * Get the endpoint registry
     * 
     * @return The endpoint registry
     */
    public EndpointRegistry getEndpointRegistry() {
        return endpointRegistry;
    }
}