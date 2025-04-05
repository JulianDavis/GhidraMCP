package com.juliandavis.ghidramcp.services;

import com.juliandavis.ghidramcp.core.service.Service;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.Msg;

import java.util.*;

/**
 * Service for handling cross-references to and from functions and addresses in Ghidra.
 */
public class FunctionXrefService implements Service {

    public static final String SERVICE_NAME = "FunctionXrefService";
    private Program program;

    /**
     * Get the service name
     *
     * @return The service name
     */
    @Override
    public String getName() {
        return SERVICE_NAME;
    }

    /**
     * Initialize the service with the current program.
     *
     * @param program the current Ghidra program
     */
    @Override
    public void initialize(Program program) {
        this.program = program;
    }

    /**
     * Dispose of service resources
     */
    @Override
    public void dispose() {
        // No resources to dispose
        this.program = null;
    }

    /**
     * Get all references to and from the specified address
     *
     * @param addressStr The address to get references for
     * @return Map containing the references information
     */
    public Map<String, Object> getReferencesAtAddress(String addressStr) {
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return createErrorResponse("Address is required");
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return createErrorResponse("Invalid address: " + addressStr);
            }

            // Get all references to this address (where this is the target)
            List<Map<String, Object>> referencesToHere = new ArrayList<>();
            ReferenceIterator refsToIter = program.getReferenceManager().getReferencesTo(address);
            while (refsToIter.hasNext()) {
                Reference ref = refsToIter.next();
                Map<String, Object> reference = new HashMap<>();
                reference.put("fromAddress", ref.getFromAddress().toString());
                reference.put("toAddress", ref.getToAddress().toString());
                reference.put("type", ref.getReferenceType().toString());
                reference.put("isData", !ref.isMemoryReference());
                reference.put("isPrimary", ref.isPrimary());

                // Add source context if it's a function
                Function fromFunc = program.getFunctionManager().getFunctionAt(ref.getFromAddress());
                if (fromFunc != null) {
                    reference.put("fromFunction", fromFunc.getName());
                    reference.put("fromFunctionOffset",
                            ref.getFromAddress().subtract(fromFunc.getEntryPoint()));
                }

                referencesToHere.add(reference);
            }

            // Get all references from this address (where this is the source)
            List<Map<String, Object>> referencesFromHere = new ArrayList<>();
            Reference[] refsFrom = program.getReferenceManager().getReferencesFrom(address);
            for (Reference ref : refsFrom) {
                Map<String, Object> reference = new HashMap<>();
                reference.put("fromAddress", ref.getFromAddress().toString());
                reference.put("toAddress", ref.getToAddress().toString());
                reference.put("type", ref.getReferenceType().toString());
                reference.put("isData", !ref.isMemoryReference());
                reference.put("isPrimary", ref.isPrimary());

                // Add target context if it's a function
                Function toFunc = program.getFunctionManager().getFunctionAt(ref.getToAddress());
                if (toFunc != null) {
                    reference.put("toFunction", toFunc.getName());
                }

                referencesFromHere.add(reference);
            }

            Map<String, Object> result = new HashMap<>();
            result.put("address", address.toString());
            result.put("referencesToHere", referencesToHere);
            result.put("referencesFromHere", referencesFromHere);
            result.put("success", true);

            return createSuccessResponse(result);

        } catch (Exception e) {
            Msg.error(this, "Error getting references for address " + addressStr, e);
            return createErrorResponse("Invalid address or error retrieving references: " + e.getMessage());
        }
    }

    /**
     * Creates a standardized error response with default error code (400)
     *
     * @param errorMessage The error message
     * @return Map representing the error response
     */
    private Map<String, Object> createErrorResponse(String errorMessage) {
        return createErrorResponse(errorMessage, 400);
    }

    /**
     * Creates a standardized error response
     *
     * @param errorMessage The error message
     * @param errorCode Optional error code
     * @return Map representing the error response
     */
    private Map<String, Object> createErrorResponse(String errorMessage, int errorCode) {
        Map<String, Object> response = new HashMap<>();
        Map<String, Object> errorDetails = new HashMap<>();

        // Standard top-level structure
        response.put("status", "error");

        // Error details
        errorDetails.put("message", errorMessage);
        errorDetails.put("code", errorCode);

        response.put("error", errorDetails);

        return response;
    }

    /**
     * Creates a standardized success response
     *
     * @param data The data to include in the response
     * @return Map representing the success response
     */
    private Map<String, Object> createSuccessResponse(Map<String, Object> data) {
        Map<String, Object> response = new HashMap<>();

        // Standard top-level structure
        response.put("status", "success");
        response.put("data", data);

        return response;
    }
}
