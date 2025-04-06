package com.juliandavis.ghidramcp.services;

import com.juliandavis.ghidramcp.api.util.ResponseUtil;
import ghidra.program.model.symbol.Symbol; // Correct import for Symbol
import com.juliandavis.ghidramcp.core.service.Service;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.pcode.HighFunctionDBUtil; // Correct import for the utility class
import ghidra.program.model.data.DataType;                 // Import DataType
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;        // Import Variable
import ghidra.program.model.listing.VariableStorage; // Import VariableStorage
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
// Removed redundant Symbol import (already imported on line 4)
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
            return ResponseUtil.createErrorResponse("No program loaded");
        }

        if (name == null || name.isEmpty()) {
            return ResponseUtil.createErrorResponse("Function name is required");
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
                return ResponseUtil.createErrorResponse("Function not found: " + name);
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
                return ResponseUtil.createSuccessResponse(response);
            } else {
                String errorMsg = result != null ? result.getErrorMessage() : "Unknown decompilation error";
                return ResponseUtil.createErrorResponse("Decompilation failed: " + errorMsg);
            }
        } catch (Exception e) {
            Msg.error(this, "Error decompiling function: " + name, e);
            return ResponseUtil.createErrorResponse("Error: " + e.getMessage());
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
            return ResponseUtil.createErrorResponse("No program loaded");
        }

        if (startAddressStr == null || startAddressStr.isEmpty()) {
            return ResponseUtil.createErrorResponse("Start address is required");
        }

        if (endAddressStr == null || endAddressStr.isEmpty()) {
            return ResponseUtil.createErrorResponse("End address is required");
        }

        DecompInterface decompInterface = null;

        try {
            // Convert address strings to Address objects
            Address startAddress = program.getAddressFactory().getAddress(startAddressStr);
            Address endAddress = program.getAddressFactory().getAddress(endAddressStr);

            if (startAddress == null) {
                return ResponseUtil.createErrorResponse("Invalid start address: " + startAddressStr);
            }

            if (endAddress == null) {
                return ResponseUtil.createErrorResponse("Invalid end address: " + endAddressStr);
            }

            // Ensure start address is before end address
            if (startAddress.compareTo(endAddress) > 0) {
                return ResponseUtil.createErrorResponse("Start address must be less than or equal to end address");
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

            return ResponseUtil.createSuccessResponse(result);

        } catch (Exception e) {
            Msg.error(this, "Error decompiling address range", e);
            return ResponseUtil.createErrorResponse("Error decompiling address range: " + e.getMessage());
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
            return ResponseUtil.createErrorResponse("No program loaded");
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return ResponseUtil.createErrorResponse("Address is required");
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return ResponseUtil.createErrorResponse("Invalid address: " + addressStr);
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
                return ResponseUtil.createSuccessResponse(result);
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
                return ResponseUtil.createSuccessResponse(result);
            }

            // No function at or containing this address
            result.put("hasFunction", false);

            // Check if this address might be a valid function start point
            if (program.getListing().getInstructionAt(address) != null) {
                result.put("hasInstruction", true);
                result.put("instruction", program.getListing().getInstructionAt(address).toString());
                result.put("mnemonic", program.getListing().getInstructionAt(address).getMnemonicString());
                result.put("message", "No function at address, but instruction found: " + program.getListing().getInstructionAt(address));
                return ResponseUtil.createSuccessResponse(result);
            }

            // Check if there is data at this address
            if (program.getListing().getDataAt(address) != null) {
                result.put("hasData", true);
                result.put("dataType", program.getListing().getDataAt(address).getDataType().getName());
                result.put("dataValue", program.getListing().getDataAt(address).getDefaultValueRepresentation());
                result.put("message", "No function at address, but data found: " + program.getListing().getDataAt(address).getDataType().getName());
                return ResponseUtil.createSuccessResponse(result);
            }

            // Nothing defined at this address
            result.put("message", "No function, instruction, or data defined at address " + address);
            return ResponseUtil.createSuccessResponse(result);

        } catch (Exception e) {
            Msg.error(this, "Error identifying function at address", e);
            return ResponseUtil.createErrorResponse("Error identifying function: " + e.getMessage());
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
            return ResponseUtil.createErrorResponse("No program loaded");
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return ResponseUtil.createErrorResponse("Address is required");
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return ResponseUtil.createErrorResponse("Invalid address: " + addressStr);
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
                return ResponseUtil.createSuccessResponse(result);
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
                return ResponseUtil.createSuccessResponse(result);
            }

            // Check if there's an instruction at this address
            if (program.getListing().getInstructionAt(address) == null && !force) {
                Map<String, Object> result = new HashMap<>();
                result.put("success", false);
                result.put("address", address.toString());
                result.put("functionCreated", false);
                result.put("message", "No instruction at " + address +
                        ". Cannot create function at non-instruction address. Use force=true to override.");
                return ResponseUtil.createSuccessResponse(result);
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

            return ResponseUtil.createSuccessResponse(result);
        } catch (Exception e) {
            Msg.error(this, "Error defining function at address", e);
            return ResponseUtil.createErrorResponse("Error defining function: " + e.getMessage());
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
            return ResponseUtil.createErrorResponse("No program loaded");
        }

        if (oldName == null || oldName.isEmpty()) {
            return ResponseUtil.createErrorResponse("Old function name is required");
        }

        if (newName == null || newName.isEmpty()) {
            return ResponseUtil.createErrorResponse("New function name is required");
        }

        // Check if the new name is valid (not necessary in all cases but good practice)
        if (!isValidSymbolName(newName)) {
            return ResponseUtil.createErrorResponse("Invalid function name: " + newName);
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
                return ResponseUtil.createErrorResponse("Function not found: " + oldName);
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

            return ResponseUtil.createSuccessResponse(response);
        } catch (Exception e) {
            Msg.error(this, "Error renaming function", e);
            return ResponseUtil.createErrorResponse("Error: " + e.getMessage());
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
            return ResponseUtil.createErrorResponse("No program loaded");
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return ResponseUtil.createErrorResponse("Address is required");
        }

        if (newName == null || newName.isEmpty()) {
            return ResponseUtil.createErrorResponse("New name is required");
        }

        // Check if the new name is valid
        if (!isValidSymbolName(newName)) {
            return ResponseUtil.createErrorResponse("Invalid symbol name: " + newName);
        }

        boolean success = false;
        String message;

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return ResponseUtil.createErrorResponse("Invalid address: " + addressStr);
            }

            // Check if there is data at this address
            if (program.getListing().getDataAt(address) == null) {
                return ResponseUtil.createErrorResponse("No data found at address: " + addressStr);
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

            return ResponseUtil.createSuccessResponse(response); // Already correct, but included for completeness
        } catch (Exception e) {
            Msg.error(this, "Error renaming data", e);
            return ResponseUtil.createErrorResponse("Error: " + e.getMessage());
        }
    }


/**
 * Rename a variable within a function's decompiled view.
 *
 * @param functionName The name of the function containing the variable.
 * @param variableName The current name of the variable to rename.
 * @param newName      The new name for the variable.
 * @return Map containing the result of the rename operation.
 */
public Map<String, Object> renameVariableInFunction(String functionName, String variableName, String newName) {
        // Removed declaration from here. It will be declared below.
    if (program == null) {
        return ResponseUtil.createErrorResponse("No program loaded");
    }

    if (functionName == null || functionName.isEmpty()) {
        return ResponseUtil.createErrorResponse("Function name is required");
    }

    if (variableName == null || variableName.isEmpty()) {
        return ResponseUtil.createErrorResponse("Current variable name is required");
    }

    if (newName == null || newName.isEmpty()) {
        return ResponseUtil.createErrorResponse("New variable name is required");
    }

    // Validate the new name
    if (!isValidSymbolName(newName)) {
        return ResponseUtil.createErrorResponse("Invalid new variable name: " + newName);
    }

    DecompInterface decomp = null;
    boolean success = false;
    String message = "Variable rename failed";
    Symbol targetSymbol = null;
    ghidra.program.model.pcode.HighSymbol targetHighSymbol = null; // Declare targetHighSymbol here
    Function function = null;

    try {
        // Find the function by name
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(functionName)) {
                function = func;
                break;
            }
        }

        if (function == null) {
            return ResponseUtil.createErrorResponse("Function not found: " + functionName);
        }

        // Decompile to get HighFunction
        decomp = new DecompInterface();
        decomp.openProgram(program);
        DecompileResults results = decomp.decompileFunction(function, 30, new ConsoleTaskMonitor());

        if (results == null || !results.decompileCompleted()) {
            String errorMsg = results != null ? results.getErrorMessage() : "Unknown decompilation error";
            return ResponseUtil.createErrorResponse("Decompilation failed for function '" + functionName + "': " + errorMsg);
        }

        ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
        if (highFunction == null) {
            return ResponseUtil.createErrorResponse("Could not get HighFunction for '" + functionName + "'");
        }

        ghidra.program.model.pcode.LocalSymbolMap symbolMap = highFunction.getLocalSymbolMap();
        Iterator<ghidra.program.model.pcode.HighSymbol> symbolIterator = symbolMap.getSymbols();
        while (symbolIterator.hasNext()) {
            ghidra.program.model.pcode.HighSymbol highSymbol = symbolIterator.next();
            if (highSymbol.getName().equals(variableName)) {
                targetHighSymbol = highSymbol;
                targetSymbol = highSymbol.getSymbol();
                break;
            }
        }

        // Check if we found the HighSymbol
        if (targetHighSymbol == null) {
            return ResponseUtil.createErrorResponse("Variable '" + variableName + "' not found in function '" + functionName + "'");
        }

        // Attempt to rename using HighFunctionDBUtil.updateDBVariable within a transaction
        int tx = program.startTransaction("Rename variable " + variableName + " to " + newName + " in " + functionName);
        try {
            // Use the utility function to handle the rename/update in the database
            // Pass the existing data type as we only want to rename
            HighFunctionDBUtil.updateDBVariable(targetHighSymbol, newName, targetHighSymbol.getDataType(), SourceType.USER_DEFINED);
            success = true; // Assume success if no exception is thrown
            message = "Variable '" + variableName + "' renamed to '" + newName + "' successfully";
            Msg.info(this, message + " in function " + functionName);
            // Try to get the symbol now, it should exist after the update
            targetSymbol = targetHighSymbol.getSymbol();

        } catch (ghidra.util.exception.InvalidInputException e) {
            message = "Rename failed: Invalid name '" + newName + "'. " + e.getMessage();
            Msg.error(this, message, e);
            success = false;
        } catch (Exception e) { // Catch other potential exceptions during updateDBVariable
            message = "Rename failed due to unexpected exception: " + e.getClass().getName() + " - " + e.getMessage();
            Msg.error(this, message, e);
            success = false;
        } finally {
            program.endTransaction(tx, success);
        }

    } catch (Exception e) { // Catch exceptions during the overall process (finding function, decompiling etc.)
        message = "Error during rename variable process: " + e.getMessage();
        Msg.error(this, message, e);
        success = false; // Ensure success is false if we land here
    } finally { // Ensure decompiler is disposed
        if (decomp != null) {
            decomp.dispose();
        }
    }

    // Prepare response
    Map<String, Object> response = new HashMap<>();
    response.put("success", success);
    response.put("functionName", functionName);
    response.put("variableName", variableName);
    response.put("newName", newName);
    response.put("message", message);

    if (success && targetSymbol != null) {
         Map<String, Object> symbolDetails = new HashMap<>();
         symbolDetails.put("name", targetSymbol.getName());
         symbolDetails.put("address", targetSymbol.getAddress().toString());
         symbolDetails.put("type", targetSymbol.getSymbolType().toString());
         response.put("symbol", symbolDetails);
    }


    if (success) {
        return ResponseUtil.createSuccessResponse(response);
    } else {
        // Use the existing error response structure but add context
        Map<String, Object> errorData = new HashMap<>();
        errorData.put("functionName", functionName);
        errorData.put("variableName", variableName);
        errorData.put("newName", newName);
        // Need to check how createErrorResponse handles extra data or create a new helper
        // Use the new ResponseUtil, potentially adding context later if needed
        return ResponseUtil.createErrorResponse(message);
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

} // End of DecompileService class
