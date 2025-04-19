package com.juliandavis.ghidramcp.services;

import com.juliandavis.ghidramcp.core.service.Service;
import ghidra.app.cmd.label.CreateNamespacesCmd;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;

import java.util.HashMap;
import java.util.Map;

/**
 * Service for handling namespace operations within Ghidra.
 * <p>
 * This service provides methods for creating and manipulating namespaces.
 */
public class NamespaceService implements Service {

    public static final String SERVICE_NAME = "NamespaceService";
    private Program currentProgram;
    private PluginTool tool;
    private ConsoleService console;

    /**
     * Create a new NamespaceService with the specified PluginTool.
     *
     * @param tool the PluginTool instance
     */
    public NamespaceService(PluginTool tool) {
        this.tool = tool;
        this.console = tool.getService(ConsoleService.class);
        if (console == null) {
            Msg.error(this, "ConsoleService not found. Please ensure it's enabled in the tool.");
        }
    }

    @Override
    public String getName() {
        return SERVICE_NAME;
    }

    @Override
    public void initialize(Program program) {
        this.currentProgram = program;
        if (program != null) {
            Msg.info(this, SERVICE_NAME + " initialized with program: " + program.getName());
        } else {
            Msg.warn(this, SERVICE_NAME + " initialized with null program.");
        }
    }

    @Override
    public void dispose() {
        this.currentProgram = null;
        Msg.info(this, SERVICE_NAME + " disposed");
    }

    /**
     * Creates a namespace hierarchy based on the provided path string.
     *
     * @param namespacePath the path string for the namespace (e.g., "global::ns1::ns2")
     * @param source the source type for the namespace (e.g., USER_DEFINED)
     * @return a map containing the result of the operation
     */
    public Map<String, Object> createNamespace(String namespacePath, String source) {
        if (currentProgram == null) {
            return createErrorResult("No program loaded or service not initialized properly.", 503);
        }

        if (namespacePath == null || namespacePath.trim().isEmpty()) {
            return createErrorResult("Namespace path cannot be empty", 400);
        }

        // Convert source string to SourceType enum
        SourceType sourceType;
        try {
            sourceType = source != null ? SourceType.valueOf(source) : SourceType.USER_DEFINED;
        } catch (IllegalArgumentException e) {
            return createErrorResult("Invalid source type: " + source, 400);
        }

        // Create the command
        CreateNamespacesCmd cmd = new CreateNamespacesCmd(namespacePath, sourceType);

        // Execute the command
        if (tool.execute(cmd, currentProgram)) {
            Namespace resultNamespace = cmd.getNamespace();
            if (resultNamespace != null) {
                if (console != null) {
                    console.println("Successfully created namespace: " + namespacePath);
                }
                
                Map<String, Object> data = new HashMap<>();
                data.put("success", true);
                data.put("namespace", resultNamespace.getName());
                data.put("path", namespacePath);
                data.put("id", resultNamespace.getID());
                data.put("message", "Namespace created successfully");
                
                return createSuccessResult(data);
            } else {
                // This case is unexpected if cmd.applyTo() returns true
                return createErrorResult("Command executed but failed to create namespace", 500);
            }
        } else {
            String errorMsg = cmd.getStatusMsg();
            if (console != null) {
                console.printError("Failed to create namespace: " + errorMsg);
            }
            return createErrorResult("Failed to create namespace: " + errorMsg, 400);
        }
    }

    // Helper methods for standardized responses
    private Map<String, Object> createErrorResult(String errorMessage, int errorCode) {
        Map<String, Object> response = new HashMap<>();
        Map<String, Object> errorDetails = new HashMap<>();
        response.put("status", "error");
        errorDetails.put("message", errorMessage);
        errorDetails.put("code", errorCode);
        response.put("error", errorDetails);
        return response;
    }

    private Map<String, Object> createSuccessResult(Map<String, Object> data) {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("data", data);
        return response;
    }
}
