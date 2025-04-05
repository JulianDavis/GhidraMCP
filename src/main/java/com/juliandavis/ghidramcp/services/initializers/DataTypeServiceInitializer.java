package com.juliandavis.ghidramcp.services.initializers;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.services.DataTypeService;
import com.juliandavis.ghidramcp.api.handlers.DataTypeHttpHandler;
import com.juliandavis.ghidramcp.api.server.EndpointRegistry;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import com.juliandavis.ghidramcp.core.service.initializer.BaseServiceInitializer;

/**
 * Initializer for the data type service and related components.
 * <p>
 * This class is responsible for:
 * <ul>
 * <li>Creating and registering the DataTypeService with the ServiceRegistry</li>
 * <li>Creating and registering the DataTypeHttpHandler with the EndpointRegistry</li>
 * </ul>
 */
public class DataTypeServiceInitializer extends BaseServiceInitializer<DataTypeService, DataTypeHttpHandler> {
    
    /**
     * Creates a new DataTypeServiceInitializer.
     * 
     * @param plugin The GhidraMCP plugin instance
     * @param serviceRegistry The service registry
     * @param endpointRegistry The endpoint registry
     */
    public DataTypeServiceInitializer(GhidraMCPPlugin plugin, ServiceRegistry serviceRegistry, EndpointRegistry endpointRegistry) {
        super(plugin, serviceRegistry, endpointRegistry);
    }
    
    @Override
    protected DataTypeService createService() {
        return new DataTypeService();
    }
    
    @Override
    protected DataTypeHttpHandler createHttpHandler() {
        return new DataTypeHttpHandler(plugin);
    }
    
    @Override
    protected String getServiceName() {
        return "DataTypeService";
    }
    
    /**
     * Static initialization method for backward compatibility.
     * This method creates an instance of DataTypeServiceInitializer and initializes it.
     * 
     * @param plugin the GhidraMCPPlugin instance
     */
    public static void initialize(GhidraMCPPlugin plugin) {
        DataTypeServiceInitializer initializer = new DataTypeServiceInitializer(
            plugin, 
            ServiceRegistry.getInstance(), 
            plugin.getServerManager().getEndpointRegistry()
        );
        initializer.initialize();
    }
}