package com.juliandavis.ghidramcp.core.service;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Registry for all GhidraMCP services.
 * <p>
 * This class manages the lifecycle of services and provides access to registered
 * services. Services can be registered during plugin initialization and are
 * automatically initialized with the current program when it changes.
 */
public class ServiceRegistry {
    
    private static ServiceRegistry instance;
    
    private final Map<String, Service> services;
    private Program currentProgram;
    
    /**
     * Get the singleton instance of the ServiceRegistry.
     * 
     * @return the ServiceRegistry instance
     */
    public static ServiceRegistry getInstance() {
        if (instance == null) {
            instance = new ServiceRegistry();
        }
        return instance;
    }
    
    /**
     * Private constructor to enforce singleton pattern.
     */
    private ServiceRegistry() {
        services = new HashMap<>();
        currentProgram = null;
    }
    
    /**
     * Register a service with the registry.
     * <p>
     * If a service with the same name already exists, it will be replaced.
     * The newly registered service will be initialized with the current program
     * if one is loaded.
     * 
     * @param service the service to register
     */
    public void registerService(Service service) {
        String serviceName = service.getName();
        
        // Dispose of existing service with the same name if it exists
        Service existingService = services.get(serviceName);
        if (existingService != null) {
            Msg.info(this, "Replacing existing service: " + serviceName);
            existingService.dispose();
        }
        
        // Register the new service
        services.put(serviceName, service);
        
        // Initialize the service if a program is loaded
        if (currentProgram != null) {
            service.initialize(currentProgram);
        }
        
        Msg.info(this, "Registered service: " + serviceName);
    }
    
    /**
     * Get a service by name.
     * 
     * @param <T> the expected service type
     * @param serviceName the name of the service
     * @param serviceClass the class of the service
     * @return the service, or null if not found or not of the expected type
     */
    @SuppressWarnings("unchecked")
    public <T extends Service> T getService(String serviceName, Class<T> serviceClass) {
        Service service = services.get(serviceName);
        if (service == null) {
            return null;
        }
        
        if (serviceClass.isInstance(service)) {
            return (T) service;
        } else {
            Msg.warn(this, "Service " + serviceName + " is not of expected type: " + serviceClass.getName());
            return null;
        }
    }
    
    /**
     * Get all registered service names.
     * 
     * @return a set of service names
     */
    public Set<String> getServiceNames() {
        return services.keySet();
    }
    
    /**
     * Update all services with a new program.
     * <p>
     * This method is called when the current program changes.
     * 
     * @param program the new program
     */
    public void programChanged(Program program) {
        this.currentProgram = program;
        
        if (program == null) {
            // Program closed, dispose all services
            disposeAllServices();
        } else {
            // Program opened or changed, initialize all services
            services.values().forEach(service -> service.initialize(program));
        }
    }
    
    /**
     * Dispose of all registered services.
     * <p>
     * This method is called when the plugin is being deactivated.
     */
    public void disposeAllServices() {
        services.values().forEach(Service::dispose);
    }
    
    /**
     * Get the current program.
     * 
     * @return the current program, or null if no program is loaded
     */
    public Program getCurrentProgram() {
        return currentProgram;
    }
}
