package com.juliandavis.ghidramcp.core.service;

import ghidra.program.model.listing.Program;

/**
 * Base interface for all GhidraMCP services.
 * <p>
 * Services provide core functionality for the plugin and are managed by the
 * {@link ServiceRegistry}. Each service has a lifecycle with initialization and disposal
 * methods that are called by the registry.
 */
public interface Service {
    
    /**
     * Get the unique name of this service.
     * 
     * @return the service name
     */
    String getName();
    
    /**
     * Initialize the service with the current program.
     * <p>
     * This method is called by the {@link ServiceRegistry} when a new program is loaded or
     * when the service is first registered.
     * 
     * @param program the current Ghidra program
     */
    void initialize(Program program);
    
    /**
     * Dispose of any resources used by this service.
     * <p>
     * This method is called by the {@link ServiceRegistry} when a program is closed or
     * when the plugin is being deactivated.
     */
    void dispose();
}
