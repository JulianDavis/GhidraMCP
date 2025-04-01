package com.juliandavis.ghidramcp.api.server;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;

import com.juliandavis.ghidramcp.GhidraMCPPlugin;
import com.sun.net.httpserver.HttpServer;

import ghidra.util.Msg;

/**
 * Manages the HTTP server for the GhidraMCP plugin.
 * <p>
 * This class is responsible for:
 * <ul>
 * <li>Creating and configuring the HTTP server</li>
 * <li>Starting and stopping the server</li>
 * <li>Providing access to the server for handlers to register endpoints</li>
 * </ul>
 */
public class HttpServerManager {
    
    private static final int DEFAULT_PORT = 8080;
    private static final int DEFAULT_BACKLOG = 0;
    private static final int DEFAULT_THREAD_POOL_SIZE = 10;
    
    private final GhidraMCPPlugin plugin;
    private HttpServer server;
    private int port;
    private EndpointRegistry endpointRegistry;
    
    /**
     * Create a new HttpServerManager with the default port.
     * 
     * @param plugin the GhidraMCPPlugin instance
     */
    public HttpServerManager(GhidraMCPPlugin plugin) {
        this(plugin, DEFAULT_PORT);
    }
    
    /**
     * Create a new HttpServerManager with the specified port.
     * 
     * @param plugin the GhidraMCPPlugin instance
     * @param port the port to listen on
     */
    public HttpServerManager(GhidraMCPPlugin plugin, int port) {
        this.plugin = plugin;
        this.port = port;
        this.endpointRegistry = new EndpointRegistry(plugin);
    }
    
    /**
     * Start the HTTP server.
     * 
     * @throws IOException if the server could not be started
     */
    public void startServer() throws IOException {
        if (server != null) {
            Msg.warn(this, "Server already running, ignoring start request");
            return;
        }
        
        server = HttpServer.create(new InetSocketAddress(port), DEFAULT_BACKLOG);
        server.setExecutor(Executors.newFixedThreadPool(DEFAULT_THREAD_POOL_SIZE));
        
        // Register all endpoints with the server
        endpointRegistry.registerEndpoints(server);
        
        // Start the server in a new thread
        new Thread(() -> {
            server.start();
            Msg.info(this, "GhidraMCP HTTP server started on port " + port);
        }, "GhidraMCP-HTTP-Server").start();
    }
    
    /**
     * Stop the HTTP server.
     */
    public void stopServer() {
        if (server == null) {
            Msg.warn(this, "Server not running, ignoring stop request");
            return;
        }
        
        // Give connections 5 seconds to complete before stopping
        server.stop(5);
        server = null;
        
        Msg.info(this, "GhidraMCP HTTP server stopped");
    }
    
    /**
     * Get the HTTP server instance.
     * 
     * @return the HTTP server instance, or null if not started
     */
    public HttpServer getServer() {
        return server;
    }
    
    /**
     * Get the endpoint registry.
     * 
     * @return the endpoint registry
     */
    public EndpointRegistry getEndpointRegistry() {
        return endpointRegistry;
    }
    
    /**
     * Set the port to use for the HTTP server.
     * <p>
     * This will only take effect if the server is restarted.
     * 
     * @param port the port to use
     */
    public void setPort(int port) {
        this.port = port;
    }
    
    /**
     * Get the port used by the HTTP server.
     * 
     * @return the port
     */
    public int getPort() {
        return port;
    }
    
    /**
     * Check if the server is running.
     * 
     * @return true if the server is running, false otherwise
     */
    public boolean isRunning() {
        return server != null;
    }
}
