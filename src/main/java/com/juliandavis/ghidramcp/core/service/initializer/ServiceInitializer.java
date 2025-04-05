package com.juliandavis.ghidramcp.core.service.initializer;

/**
 * Interface for initializing services and their HTTP handlers.
 * <p>
 * This interface defines the contract for service initializers.
 */
public interface ServiceInitializer {
    
    /**
     * Initialize the service and its HTTP handler.
     * 
     * @return true if initialization succeeded, false otherwise
     */
    boolean initialize();
    
    /**
     * Dispose of the service and its resources.
     */
    default void dispose() {
        // Default implementation does nothing
    }
}
