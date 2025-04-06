package com.juliandavis.ghidramcp.services;

import com.juliandavis.ghidramcp.core.service.Service; // Import Service interface
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

import java.util.HashMap;
import java.util.Map;

public class MemoryManipulationService implements Service { // Implement Service

    public static final String SERVICE_NAME = "MemoryManipulationService";
    private FlatProgramAPI flatApi;
    private Program currentProgram;
    private PluginTool tool;
    private ConsoleService console;


    // Constructor now takes PluginTool
    public MemoryManipulationService(PluginTool tool) {
        this.tool = tool;
        this.console = tool.getService(ConsoleService.class);
        if (console == null) {
            Msg.error(this, "ConsoleService not found. Please ensure it's enabled in the tool.");
        }
    }

    // Implementation of Service interface methods
    @Override
    public String getName() {
        return SERVICE_NAME;
    }

    @Override
    public void initialize(Program program) {
        this.currentProgram = program;
        if (program != null) {
            this.flatApi = new FlatProgramAPI(program); // Initialize flatApi here
            Msg.info(this, SERVICE_NAME + " initialized with program: " + program.getName());
        } else {
            this.flatApi = null;
            Msg.warn(this, SERVICE_NAME + " initialized with null program.");
        }
    }

    @Override
    public void dispose() {
        this.currentProgram = null;
        this.flatApi = null;
        Msg.info(this, SERVICE_NAME + " disposed");
    }

    // Helper methods for standardized responses (similar to MemoryReadService)
    private Map<String, Object> createErrorResult(String errorMessage, int errorCode) {
        Map<String, Object> response = new HashMap<>();
        Map<String, Object> errorDetails = new HashMap<>();
        response.put("status", "error");
        errorDetails.put("message", errorMessage);
        errorDetails.put("code", errorCode);
        response.put("error", errorDetails);
        return response;
    }

    private Map<String, Object> createErrorResult(String errorMessage) {
        return createErrorResult(errorMessage, 400); // Default to 400 Bad Request
    }

     private Map<String, Object> createSuccessResult(Map<String, Object> data) {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("data", data);
        return response;
    }

    /**
     * Clears the listing (code/data) in the specified memory range.
     *
     * @param startAddressStr The starting address string (e.g., "0x1400").
     * @param endAddressStr   The ending address string (inclusive, e.g., "0x14ff").
     * @return A map indicating success or an error map on failure.
     */
    public Map<String, Object> clearMemoryRange(String startAddressStr, String endAddressStr) { // Ensure return type is correct
        if (currentProgram == null || flatApi == null) { // Check flatApi too
            return createErrorResult("No program loaded or service not initialized.");
        }

        Address startAddress;
        Address endAddress;

        // Use AddressFactory for parsing
        startAddress = currentProgram.getAddressFactory().getAddress(startAddressStr);
        if (startAddress == null) {
             // Return error map instead of throwing exception
            return createErrorResult("Invalid start address format or value: " + startAddressStr);
        } // End of startAddress check

        // Use AddressFactory for parsing endAddress
        endAddress = currentProgram.getAddressFactory().getAddress(endAddressStr);
        if (endAddress == null) {
            // Return error map if endAddress is invalid
           return createErrorResult("Invalid end address format or value: " + endAddressStr);
       } // End of endAddress check

        // Now that both addresses are parsed, proceed with validation and clearing
        // --- Start of main logic block ---
        int transactionId = 0; // Initialize outside try
        boolean success = false;
        try {
            // Validate address order *before* starting transaction
            if (startAddress.compareTo(endAddress) > 0) {
                 // No transaction started yet, just return error
                return createErrorResult("Start address cannot be after end address.");
            }

            // Start transaction only if addresses are valid and in order
            transactionId = currentProgram.startTransaction("Clear Memory Range");
            if (console != null) console.println("Clearing memory range from " + startAddress + " to " + endAddress);
            flatApi.clearListing(startAddress, endAddress);
            success = true;
            if (console != null) console.println("Successfully cleared memory range.");

            Map<String, Object> data = new HashMap<>();
            data.put("success", true); // Keep simple success flag inside data for now
            data.put("startAddress", startAddress.toString());
            data.put("endAddress", endAddress.toString());
            data.put("message", "Memory range cleared successfully.");
            return createSuccessResult(data); // Use success helper
        } catch (CancelledException ce) { // Rename variable 'e' to 'ce'
            if (console != null) console.printError("Memory clearing cancelled by user.");
            // Note: Transaction might not have started if validation failed, but endTransaction handles id=0
            return createErrorResult("Operation cancelled by user.", 499);
        } catch (Exception ex) { // Rename variable 'e' to 'ex'
            Msg.error(this, "Error clearing memory range", ex); // Use 'ex'
            if (console != null) console.printError("Error clearing memory range: " + ex.getMessage());
            return createErrorResult("Failed to clear memory range: " + ex.getMessage(), 500); // Use 'ex'
        } finally {
            currentProgram.endTransaction(transactionId, success);
        }
    }
}
