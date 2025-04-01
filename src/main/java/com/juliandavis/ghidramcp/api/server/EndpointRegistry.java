package com.juliandavis.ghidramcp.api.server;

import java.util.ArrayList;
import java.util.List;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.juliandavis.ghidramcp.api.handlers.BaseHttpHandler;
import com.sun.net.httpserver.HttpServer;

import ghidra.util.Msg;

/**
 * Registry for HTTP endpoints in the GhidraMCP plugin.
 * <p>
 * This class manages the registration of HTTP handlers and endpoints with the HTTP server.
 * It allows handlers to be registered with the plugin and endpoints to be associated
 * with specific URI paths.
 */
public class EndpointRegistry {
    
    private final GhidraMCPPlugin plugin;
    private final List<BaseHttpHandler> handlers;
    
    /**
     * Create a new EndpointRegistry.
     * 
     * @param plugin the GhidraMCPPlugin instance
     */
    public EndpointRegistry(GhidraMCPPlugin plugin) {
        this.plugin = plugin;
        this.handlers = new ArrayList<>();
    }
    
    /**
     * Register a handler with the registry.
     * <p>
     * The handler will be retained for later registration with the HTTP server.
     * 
     * @param handler the handler to register
     */
    public void registerHandler(BaseHttpHandler handler) {
        handlers.add(handler);
        Msg.info(this, "Registered handler: " + handler.getClass().getSimpleName());
    }
    
    /**
     * Register all handlers with the HTTP server.
     * <p>
     * This method calls {@link BaseHttpHandler#registerEndpoints()} on each registered handler,
     * allowing them to register their endpoints with the server.
     * 
     * @param server the HTTP server to register with
     */
    public void registerEndpoints(HttpServer server) {
        if (server == null) {
            Msg.error(this, "Cannot register endpoints: server is null");
            return;
        }
        
        for (BaseHttpHandler handler : handlers) {
            handler.registerEndpoints();
        }
        
        Msg.info(this, "Registered " + handlers.size() + " handlers with HTTP server");
    }
    
    /**
     * Get all registered handlers.
     * 
     * @return a list of all registered handlers
     */
    public List<BaseHttpHandler> getHandlers() {
        return new ArrayList<>(handlers);
    }
    
    /**
     * Clear all registered handlers.
     */
    public void clearHandlers() {
        handlers.clear();
        Msg.info(this, "Cleared all registered handlers");
    }
}
