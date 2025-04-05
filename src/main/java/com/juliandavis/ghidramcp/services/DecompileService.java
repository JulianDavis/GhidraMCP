package com.juliandavis.ghidramcp.services;

import com.juliandavis.ghidramcp.core.service.Service;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.*;

/**
 * Service for decompiling code and managing functions in Ghidra.
 */
public class DecompileService implements Service {

    public static final String SERVICE_NAME = "DecompileService";
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
     * Decompile a function by name
     *
     * @param name Function name to decompile
     * @return Map containing the decompiled code
     */
    public Map<String, Object> decompileFunctionByName(String name) {
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        if (name == null || name.isEmpty()) {
            return createErrorResponse("Function name is required");
        }

        DecompInterface decomp = null;

        try {
            // Find the function by name
            Function function = null;
            for (Function func : program.getFunctionManager().getFunctions(true)) {
                if (func.getName().equals(name)) {
                    function = func;
                    break;
                }
            }

            if (function == null) {
                return createErrorResponse("Function not found: " + name);
            }

            // Create and initialize decompiler interface
            decomp = new DecompInterface();
            decomp.openProgram(program);

            // Decompile the function
            DecompileResults result = decomp.decompileFunction(function, 30, new ConsoleTaskMonitor());

            Map<String, Object> response = new HashMap<>();
            if (result != null && result.decompileCompleted()) {
                response.put("function", name);
                response.put("decompiled", result.getDecompiledFunction().getC());
                response.put("success", true);
                response.put("signature", function.getSignature().toString());
                response.put("address", function.getEntryPoint().toString());
                return createSuccessResponse(response);
            } else {
                String errorMsg = result != null ? result.getErrorMessage() : "Unknown decompilation error";
                return createErrorResponse("Decompilation failed: " + errorMsg);
            }
        } catch (Exception e) {
            Msg.error(this, "Error decompiling function: " + name, e);
            return createErrorResponse("Error: " + e.getMessage());
        } finally {
            if (decomp != null) {
                decomp.dispose();
            }
        }
    }

    /**
     * Decompile code within a specified address range
     *
     * @param startAddressStr The starting address as a string
     * @param endAddressStr The ending address as a string
     * @return Map containing the decompilation results
     */
    public Map<String, Object> decompileAddressRange(String startAddressStr, String endAddressStr) {
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        if (startAddressStr == null || startAddressStr.isEmpty()) {
            return createErrorResponse("Start address is required");
        }

        if (endAddressStr == null || endAddressStr.isEmpty()) {
            return createErrorResponse("End address is required");
        }

        DecompInterface decompInterface = null;

        try {
            // Convert address strings to Address objects
            Address startAddress = program.getAddressFactory().getAddress(startAddressStr);
            Address endAddress = program.getAddressFactory().getAddress(endAddressStr);

            if (startAddress == null) {
                return createErrorResponse("Invalid start address: " + startAddressStr);
            }

            if (endAddress == null) {
                return createErrorResponse("Invalid end address: " + endAddressStr);
            }

            // Ensure start address is before end address
            if (startAddress.compareTo(endAddress) > 0) {
                return createErrorResponse("Start address must be less than or equal to end address");
            }

            // Create the decompiler interface
            decompInterface = new DecompInterface();
            decompInterface.openProgram(program);

            Map<String, Object> result = new HashMap<>();
            result.put("startAddress", startAddress.toString());
            result.put("endAddress", endAddress.toString());

            // Track functions successfully decompiled and those that failed
            List<Map<String, Object>> decompiled = new ArrayList<>();
            List<Map<String, Object>> failed = new ArrayList<>();

            // Find all functions that fall within the address range
            for (Function function : program.getFunctionManager().getFunctions(startAddress, true)) {
                // Stop if we've passed the end address
                if (function.getEntryPoint().compareTo(endAddress) > 0) {
                    break;
                }

                Map<String, Object> functionResult = new HashMap<>();
                functionResult.put("name", function.getName());
                functionResult.put("entryPoint", function.getEntryPoint().toString());

                // Decompile the function
                DecompileResults decompileResults = decompInterface.decompileFunction(
                        function, decompInterface.getOptions().getDefaultTimeout(), new ConsoleTaskMonitor());

                if (decompileResults != null && decompileResults.decompileCompleted()) {
                    // Decompilation succeeded
                    String code = decompileResults.getDecompiledFunction().getC();
                    functionResult.put("code", code);
                    decompiled.add(functionResult);
                } else {
                    // Decompilation failed
                    String errorMessage = decompileResults != null ?
                            decompileResults.getErrorMessage() : "Unknown decompilation error";
                    functionResult.put("error", errorMessage);
                    failed.add(functionResult);
                }
            }

            // Check if any address in the range is not covered by a function
            boolean hasUndefinedSpace = false;
            Address current = startAddress;
            while (current.compareTo(endAddress) <= 0) {
                Function func = program.getFunctionManager().getFunctionContaining(current);
                if (func == null) {
                    hasUndefinedSpace = true;
                    break;
                }
                // Move to the end of the current function or the next code unit if no function
                Address funcEnd = func.getBody().getMaxAddress();
                current = funcEnd.add(1);
            }

            // Complete the result
            result.put("success", true);
            result.put("decompiled", decompiled);
            result.put("failed", failed);
            result.put("totalFunctions", decompiled.size() + failed.size());
            result.put("hasUndefinedSpace", hasUndefinedSpace);

            if (decompiled.isEmpty() && failed.isEmpty()) {
                result.put("message", "No functions found in the specified address range");
            }

            return createSuccessResponse(result);

        } catch (Exception e) {
            Msg.error(this, "Error decompiling address range", e);
            return createErrorResponse("Error decompiling address range: " + e.getMessage());
        } finally {
            if (decompInterface != null) {
                decompInterface.dispose();
            }
        }
    }

    /**
     * Identify if a function exists at the specified address and return information about it
     *
     * @param addressStr The address to check as a string
     * @return Map containing information about the function or status
     */
    public Map<String, Object> identifyFunctionAtAddress(String addressStr) {
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

            // Check if a function exists at the specified address
            Function functionAt = program.getFunctionManager().getFunctionAt(address);
            Function functionContaining = program.getFunctionManager().getFunctionContaining(address);

            Map<String, Object> result = new HashMap<>();
            result.put("address", address.toString());
            result.put("success", true);

            // Function exists at this exact address
            if (functionAt != null) {
                result.put("hasFunction", true);
                result.put("functionType", "entry_point");
                result.put("function", getFunctionDetails(functionAt));
                result.put("message", "Function '" + functionAt.getName() + "' starts at " + address);
                return createSuccessResponse(result);
            }

            // Address is within a function but not at the entry point
            if (functionContaining != null) {
                result.put("hasFunction", true);
                result.put("functionType", "containing");
                result.put("function", getFunctionDetails(functionContaining));

                // Calculate offset from function entry point
                long offset = address.subtract(functionContaining.getEntryPoint());
                result.put("offsetFromEntry", offset);
                result.put("message", "Address is within function '" + functionContaining.getName() +
                        "' at offset " + offset + " bytes from entry point");
                return createSuccessResponse(result);
            }

            // No function at or containing this address
            result.put("hasFunction", false);

            // Check if this address might be a valid function start point
            if (program.getListing().getInstructionAt(address) != null) {
                result.put("hasInstruction", true);
                result.put("instruction", program.getListing().getInstructionAt(address).toString());
                result.put("mnemonic", program.getListing().getInstructionAt(address).getMnemonicString());
                result.put("message", "No function at address, but instruction found: " + program.getListing().getInstructionAt(address));
                return createSuccessResponse(result);
            }

            // Check if there is data at this address
            if (program.getListing().getDataAt(address) != null) {
                result.put("hasData", true);
                result.put("dataType", program.getListing().getDataAt(address).getDataType().getName());
                result.put("dataValue", program.getListing().getDataAt(address).getDefaultValueRepresentation());
                result.put("message", "No function at address, but data found: " + program.getListing().getDataAt(address).getDataType().getName());
                return createSuccessResponse(result);
            }

            // Nothing defined at this address
            result.put("message", "No function, instruction, or data defined at address " + address);
            return createSuccessResponse(result);

        } catch (Exception e) {
            Msg.error(this, "Error identifying function at address", e);
            return createErrorResponse("Error identifying function: " + e.getMessage());
        }
    }

    /**
     * Define a function at the specified address if one doesn't exist
     *
     * @param addressStr The address to create the function at
     * @param name Optional name for the new function (null for default naming)
     * @param force Whether to force creation even if heuristics suggest it's not a valid function
     * @return Map containing the result of the function creation attempt
     */
    public Map<String, Object> defineFunctionAtAddress(String addressStr, String name, boolean force) {
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

            // Check if a function already exists at this address
            Function existingFunction = program.getFunctionManager().getFunctionAt(address);
            if (existingFunction != null) {
                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("address", address.toString());
                result.put("functionCreated", false);
                result.put("message", "Function already exists at " + address);
                result.put("function", getFunctionDetails(existingFunction));
                return createSuccessResponse(result);
            }

            // Check if this address is within an existing function
            Function containingFunction = program.getFunctionManager().getFunctionContaining(address);
            if (containingFunction != null && !force) {
                Map<String, Object> result = new HashMap<>();
                result.put("success", false);
                result.put("address", address.toString());
                result.put("functionCreated", false);
                result.put("message", "Address " + address + " is within existing function '" +
                        containingFunction.getName() + "'. Use force=true to override.");
                result.put("containingFunction", getFunctionDetails(containingFunction));
                return createSuccessResponse(result);
            }

            // Check if there's an instruction at this address
            if (program.getListing().getInstructionAt(address) == null && !force) {
                Map<String, Object> result = new HashMap<>();
                result.put("success", false);
                result.put("address", address.toString());
                result.put("functionCreated", false);
                result.put("message", "No instruction at " + address +
                        ". Cannot create function at non-instruction address. Use force=true to override.");
                return createSuccessResponse(result);
            }

            // All checks passed or force=true, try to create the function
            boolean success = false;
            String message;
            Function newFunction = null;

            int tx = program.startTransaction("Create function at " + address);
            try {
                // If name is specified, try to create with that name
                if (name != null && !name.isEmpty()) {
                    newFunction = program.getFunctionManager().createFunction(name, address, null, SourceType.USER_DEFINED);
                } else {
                    // Use default naming
                    newFunction = program.getFunctionManager().createFunction(null, address, null, SourceType.DEFAULT);
                }

                success = newFunction != null;
                message = success ? "Function created successfully" : "Failed to create function";
            } catch (Exception e) {
                message = "Error creating function: " + e.getMessage();
                Msg.error(this, message, e);
            } finally {
                program.endTransaction(tx, success);
            }

            // Prepare response
            Map<String, Object> result = new HashMap<>();
            result.put("success", success);
            result.put("address", address.toString());
            result.put("functionCreated", success);
            result.put("message", message);

            if (success) {
                result.put("function", getFunctionDetails(newFunction));
            }

            return createSuccessResponse(result);
        } catch (Exception e) {
            Msg.error(this, "Error defining function at address", e);
            return createErrorResponse("Error defining function: " + e.getMessage());
        }
    }

    /**
     * Rename a function
     *
     * @param oldName Current function name
     * @param newName New function name
     * @return Map containing the result of the rename operation
     */
    public Map<String, Object> renameFunction(String oldName, String newName) {
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        if (oldName == null || oldName.isEmpty()) {
            return createErrorResponse("Old function name is required");
        }

        if (newName == null || newName.isEmpty()) {
            return createErrorResponse("New function name is required");
        }

        // Check if the new name is valid (not necessary in all cases but good practice)
        if (!isValidSymbolName(newName)) {
            return createErrorResponse("Invalid function name: " + newName);
        }

        boolean success = false;
        String message;

        try {
            // Find the function by name
            Function function = null;
            for (Function func : program.getFunctionManager().getFunctions(true)) {
                if (func.getName().equals(oldName)) {
                    function = func;
                    break;
                }
            }

            if (function == null) {
                return createErrorResponse("Function not found: " + oldName);
            }

            // Attempt to rename the function
            int tx = program.startTransaction("Rename function " + oldName + " to " + newName);
            try {
                function.setName(newName, SourceType.USER_DEFINED);
                success = true;
                message = "Renamed successfully";
            } catch (Exception e) {
                message = "Rename failed: " + e.getMessage();
                Msg.error(this, message, e);
            } finally {
                program.endTransaction(tx, success);
            }

            Map<String, Object> response = new HashMap<>();
            response.put("success", success);
            response.put("oldName", oldName);
            response.put("newName", newName);
            response.put("message", message);

            if (success) {
                response.put("function", getFunctionDetails(function));
            }

            return createSuccessResponse(response);
        } catch (Exception e) {
            Msg.error(this, "Error renaming function", e);
            return createErrorResponse("Error: " + e.getMessage());
        }
    }

    /**
     * Rename a data item at the specified address
     *
     * @param addressStr Address of the data item
     * @param newName New name for the data item
     * @return Map containing the result of the rename operation
     */
    public Map<String, Object> renameDataAtAddress(String addressStr, String newName) {
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return createErrorResponse("Address is required");
        }

        if (newName == null || newName.isEmpty()) {
            return createErrorResponse("New name is required");
        }

        // Check if the new name is valid
        if (!isValidSymbolName(newName)) {
            return createErrorResponse("Invalid symbol name: " + newName);
        }

        boolean success = false;
        String message;

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return createErrorResponse("Invalid address: " + addressStr);
            }

            // Check if there is data at this address
            if (program.getListing().getDataAt(address) == null) {
                return createErrorResponse("No data found at address: " + addressStr);
            }

            // Get the symbol at this address
            Symbol primarySymbol = program.getSymbolTable().getPrimarySymbol(address);
            if (primarySymbol == null) {
                // No symbol exists, create a new one
                int tx = program.startTransaction("Create label at " + address);
                try {
                    program.getSymbolTable().createLabel(address, newName, SourceType.USER_DEFINED);
                    success = true;
                    message = "Created new label at " + addressStr;
                } catch (Exception e) {
                    message = "Failed to create label: " + e.getMessage();
                    Msg.error(this, message, e);
                } finally {
                    program.endTransaction(tx, success);
                }
            } else {
                // Symbol exists, rename it
                int tx = program.startTransaction("Rename data at " + address);
                try {
                    primarySymbol.setName(newName, SourceType.USER_DEFINED);
                    success = true;
                    message = "Renamed successfully";
                } catch (Exception e) {
                    message = "Rename failed: " + e.getMessage();
                    Msg.error(this, message, e);
                } finally {
                    program.endTransaction(tx, success);
                }
            }

            Map<String, Object> response = new HashMap<>();
            response.put("success", success);
            response.put("address", addressStr);
            response.put("newName", newName);
            response.put("message", message);

            // Include data details if available
            if (program.getListing().getDataAt(address) != null) {
                response.put("dataType", program.getListing().getDataAt(address).getDataType().getName());
                response.put("dataValue", program.getListing().getDataAt(address).getDefaultValueRepresentation());
            }

            return createSuccessResponse(response);
        } catch (Exception e) {
            Msg.error(this, "Error renaming data", e);
            return createErrorResponse("Error: " + e.getMessage());
        }
    }

    /**
     * Get detailed information about a function
     *
     * @param function The function to get details for
     * @return Map containing function details
     */
    private Map<String, Object> getFunctionDetails(Function function) {
        Map<String, Object> details = new HashMap<>();
        details.put("name", function.getName());
        details.put("address", function.getEntryPoint().toString());
        details.put("signature", function.getSignature().toString());
        details.put("returnType", function.getReturnType().toString());
        details.put("parameterCount", function.getParameterCount());
        details.put("body", Map.of(
                "minAddress", function.getBody().getMinAddress().toString(),
                "maxAddress", function.getBody().getMaxAddress().toString(),
                "numAddresses", function.getBody().getNumAddresses()
        ));

        // Include namespace information
        details.put("namespace", function.getParentNamespace().getName());

        // Include calling convention if available
        if (function.getCallingConvention() != null) {
            details.put("callingConvention", function.getCallingConvention().toString());
        }

        // Include function flags
        details.put("isExternal", function.isExternal());
        details.put("isThunk", function.isThunk());
        details.put("hasVarArgs", function.hasVarArgs());
        details.put("hasNoReturn", function.hasNoReturn());

        // Get parameter details if available
        List<Map<String, Object>> parameters = new ArrayList<>();
        for (int i = 0; i < function.getParameterCount(); i++) {
            Map<String, Object> param = new HashMap<>();
            param.put("name", function.getParameter(i).getName());
            param.put("dataType", function.getParameter(i).getDataType().getName());
            param.put("ordinal", function.getParameter(i).getOrdinal());
            parameters.add(param);
        }
        details.put("parameters", parameters);

        // Add stack frame size if available
        if (function.getStackFrame() != null) {
            details.put("stackFrameSize", function.getStackFrame().getFrameSize());
        }

        return details;
    }

    /**
     * Check if a name is valid for a symbol
     *
     * @param name The name to check
     * @return True if the name is valid, false otherwise
     */
    private boolean isValidSymbolName(String name) {
        // Basic validation - can be expanded based on specific requirements
        if (name == null || name.isEmpty()) {
            return false;
        }

        // Check for invalid characters - this is a simplified check
        return !name.contains(" ") && !name.contains("\t") && !name.contains("\n");
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
