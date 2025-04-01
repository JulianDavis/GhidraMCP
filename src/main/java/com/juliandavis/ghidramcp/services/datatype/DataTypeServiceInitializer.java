package com.juliandavis.ghidramcp.services.datatype;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.api.server.EndpointRegistry;
import com.juliandavis.ghidramcp.core.service.ServiceRegistry;
import ghidra.util.Msg;

/**
 * Initializer for the data type service and related components.
 * <p>
 * This class is responsible for:
 * <ul>
 * <li>Creating and registering the DataTypeService with the ServiceRegistry</li>
 * <li>Creating and registering the DataTypeHttpHandler with the EndpointRegistry</li>
 * </ul>
 */
public class DataTypeServiceInitializer {
    
    /**
     * Initialize the data type service and related components.
     * 
     * @param plugin the GhidraMCPPlugin instance
     */
    public static void initialize(GhidraMCPPlugin plugin) {
        // Create and register the DataTypeService
        DataTypeService dataTypeService = new DataTypeService();
        ServiceRegistry.getInstance().registerService(dataTypeService);
        
        // Create and register the DataTypeHttpHandler
        DataTypeHttpHandler dataTypeHttpHandler = new DataTypeHttpHandler(plugin);
        plugin.getServerManager().getEndpointRegistry().registerHandler(dataTypeHttpHandler);
        
        Msg.info(DataTypeServiceInitializer.class, "DataTypeService initialized");
    }
}
