package com.juliandavis.ghidramcp.services;

import com.juliandavis.ghidramcp.api.util.ResponseUtil;
import ghidra.program.model.symbol.Symbol;
import com.juliandavis.ghidramcp.core.service.Service;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.data.DataType;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.*;
import ghidra.app.cmd.function.SetVariableDataTypeCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypeConflictHandler;

/**
 * Service for decompiling code and managing functions in Ghidra.
 */
public class DecompileService implements Service {

    public static final String SERVICE_NAME = "DecompileService";
    private Program program;
    private PluginTool tool; // Add field to store the tool
     // Constructor to accept PluginTool
     public DecompileService(PluginTool tool) {
         this.tool = tool;
     }


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
            Function function = findFunctionByName(name); // Use helper

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
            Function function = findFunctionByName(oldName); // Use helper

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

        if (!isValidSymbolName(newName)) {
            return ResponseUtil.createErrorResponse("Invalid data name: " + newName);
        }

        boolean success = false;
        String message;

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return ResponseUtil.createErrorResponse("Invalid address: " + addressStr);
            }

            Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
            if (symbol == null) {
                return ResponseUtil.createErrorResponse("No primary symbol found at address: " + addressStr);
            }

            int tx = program.startTransaction("Rename data at " + addressStr + " to " + newName);
            try {
                symbol.setName(newName, SourceType.USER_DEFINED);
                success = true;
                message = "Data renamed successfully";
            } catch (Exception e) {
                message = "Rename failed: " + e.getMessage();
                Msg.error(this, message, e);
            } finally {
                program.endTransaction(tx, success);
            }

            Map<String, Object> response = new HashMap<>();
            response.put("success", success);
            response.put("address", addressStr);
            response.put("newName", newName);
            response.put("message", message);

            return ResponseUtil.createSuccessResponse(response);
        } catch (Exception e) {
            Msg.error(this, "Error renaming data", e);
            return ResponseUtil.createErrorResponse("Error: " + e.getMessage());
        }
    }


    /**
     * Rename a variable within a function's decompiled view
     *
     * @param functionName The name of the function containing the variable.
     * @param variableName The current name of the variable to rename.
     * @param newName      The new name for the variable.
     * @return Map containing the result of the rename operation.
     */
    public Map<String, Object> renameVariableInFunction(String functionName, String variableName, String newName) {
        if (program == null) {
            return ResponseUtil.createErrorResponse("No program loaded");
        }
        if (functionName == null || functionName.isEmpty() || variableName == null || variableName.isEmpty() || newName == null || newName.isEmpty()) {
            return ResponseUtil.createErrorResponse("Missing required parameters: functionName, variableName, newName");
        }

        if (!isValidSymbolName(newName)) {
            return ResponseUtil.createErrorResponse("Invalid variable name: " + newName);
        }

        Function function = findFunctionByName(functionName); // Use helper
        if (function == null) {
            return ResponseUtil.createErrorResponse("Function not found: " + functionName);
        }

        Variable variable = findVariableByName(function, variableName); // Use helper
        if (variable == null) {
            return ResponseUtil.createErrorResponse("Variable '" + variableName + "' not found in function '" + functionName + "'");
        }

        boolean success = false;
        String message;
        int tx = program.startTransaction("Rename variable " + variableName + " in " + functionName);
        try {
            variable.setName(newName, SourceType.USER_DEFINED);
            // Optionally, update the source type if needed
            // variable.setSource(SourceType.USER_DEFINED);
            success = true;
            message = "Variable renamed successfully";
        } catch (Exception e) {
            message = "Rename failed: " + e.getMessage();
            Msg.error(this, message, e);
        } finally {
            program.endTransaction(tx, success);
        }

        Map<String, Object> response = new HashMap<>();
        response.put("success", success);
        response.put("functionName", functionName);
        response.put("variableName", variableName);
        response.put("newName", newName);
        response.put("message", message);

        if (success) {
            // Optionally include updated variable details
            Map<String, Object> varDetails = new HashMap<>();
            varDetails.put("name", variable.getName());
            varDetails.put("dataType", variable.getDataType().getPathName());
            varDetails.put("storage", variable.getVariableStorage().toString());
            response.put("variable", varDetails);
        }

        return ResponseUtil.createSuccessResponse(response);
    } // End of renameVariableInFunction

    /**
     * Set the data type for a local variable or parameter within a function.
     *
     * @param functionName   The name of the function containing the variable.
     * @param variableName   The name of the variable (parameter or local) to re-type.
     * @param dataTypeName   The name/path of the data type to apply (e.g., "/DWORD", "/AI_LogContext").
     * @return Map containing the result of the operation.
     */
    public Map<String, Object> setVariableDataType(String functionName, String variableName, String dataTypeName) {
        if (program == null) {
            return ResponseUtil.createErrorResponse("No program loaded");
        }
        if (functionName == null || functionName.isEmpty() || variableName == null || variableName.isEmpty() || dataTypeName == null || dataTypeName.isEmpty()) {
            return ResponseUtil.createErrorResponse("Missing required parameters: functionName, variableName, dataTypeName");
        }

        // Use the tool instance stored in the service
        if (this.tool == null) {
             Msg.error(this, "PluginTool instance was not injected into DecompileService.");
             return ResponseUtil.createErrorResponse("PluginTool instance not available in service");
        }

        Function function = findFunctionByName(functionName);
        if (function == null) {
            return ResponseUtil.createErrorResponse("Function not found: " + functionName);
        }

        Variable variable = findVariableByName(function, variableName);
        if (variable == null) {
            Msg.warn(this, "Variable '" + variableName + "' not found by name in function '" + functionName + "'. Name lookup only currently supported.");
            return ResponseUtil.createErrorResponse("Variable '" + variableName + "' not found by name in function '" + functionName + "'");
        }

        DataTypeManager dtm = program.getDataTypeManager();
        // Use findDataType which searches by path
        DataType dataType = dtm.findDataType(dataTypeName);

        if (dataType == null) {
             // Optionally, try parsing as a C type string if findDataType fails?
             // try {
             //     DataType parsedType = CParserUtils.parseDataType(dataTypeName, dtm);
             //     if (parsedType != null) dataType = parsedType;
             // } catch (Exception parseEx) {
             //     Msg.warn(this, "Failed to parse data type string: " + dataTypeName, parseEx);
             // }
             // if (dataType == null) { // Check again after trying parse
                 return ResponseUtil.createErrorResponse("Data type not found: " + dataTypeName + ". Ensure the full path is provided if necessary (e.g., /DWORD, /Category/MyStruct).");
             // }
        }

         // Ensure the data type is resolved against the program's data type manager
        dataType = dtm.resolve(dataType, DataTypeConflictHandler.DEFAULT_HANDLER);


        // Use SetVariableDataTypeCmd(Variable var, DataType type, SourceType source)
        SetVariableDataTypeCmd cmd = new SetVariableDataTypeCmd(variable, dataType, SourceType.USER_DEFINED);

        boolean success = false;
        String message = "";

        // Execute the command
        success = tool.execute(cmd, program);
        message = success ? "Data type set successfully" : cmd.getStatusMsg(); // Get status message from command

        if (success) {
            Map<String, Object> result = new HashMap<>();
            result.put("functionName", functionName);
            result.put("variableName", variableName);
            result.put("newDataType", dataType.getPathName()); // Use path name for clarity
            result.put("message", message);
            return ResponseUtil.createSuccessResponse(result);
        } else {
            Msg.error(this, "Failed to execute SetVariableDataTypeCmd for variable '" + variableName + "': " + message);
            return ResponseUtil.createErrorResponse("Failed to set data type for variable '" + variableName + "': " + message);
        }
    }

    // Helper method to find a variable (parameter or local) by name within a function
    private Variable findVariableByName(Function function, String variableName) {
        // Check parameters first
        for (Variable param : function.getParameters()) {
            // Handle potential default names like param_1
            if (param.getName().equals(variableName) || param.getSymbol().getName().equals(variableName)) {
                return param;
            }
        }
        // Check local variables
        for (Variable local : function.getLocalVariables()) {
             if (local.getName().equals(variableName) || local.getSymbol().getName().equals(variableName)) {
                return local;
            }
        }
        return null; // Not found
    }

    // Helper method to find function by name (extracted from decompileFunctionByName)
    private Function findFunctionByName(String name) {
         FunctionManager fm = program.getFunctionManager();
         // Try getting function by exact name first
         Iterator<Function> functions = fm.getFunctions(true); // Use Iterator
         while (functions.hasNext()) { // Iterate correctly
             Function func = functions.next();
             if (func.getName(true).equals(name)) { // Use getName(true) for namespace
                 return func;
             }
             if (func.getName().equals(name)) { // Fallback to name without namespace
                 return func;
             }
         } // End while loop
         // TODO: Add lookup by address if name fails?
         return null;
    }


    /**
     * Helper method to get function details
     *
     * @param function The function object
     * @return Map containing key details about the function
     */
     private Map<String, Object> getFunctionDetails(Function function) {
        Map<String, Object> details = new HashMap<>();
        details.put("name", function.getName());
        details.put("namespace", function.getParentNamespace().getName(true));
        details.put("entryPoint", function.getEntryPoint().toString());
        details.put("signature", function.getSignature().toString());
        details.put("stackFrameSize", function.getStackFrame().getFrameSize());
        details.put("parameterCount", function.getParameterCount());
        details.put("isExternal", function.isExternal());
        details.put("isThunk", function.isThunk());
        details.put("hasVarArgs", function.hasVarArgs());
        details.put("hasNoReturn", function.hasNoReturn());
        details.put("callingConvention", function.getCallingConventionName());

        // Add body information
        Map<String, Object> bodyDetails = new HashMap<>();
        bodyDetails.put("minAddress", function.getBody().getMinAddress().toString());
        bodyDetails.put("maxAddress", function.getBody().getMaxAddress().toString());
        bodyDetails.put("numAddresses", function.getBody().getNumAddresses());
        details.put("body", bodyDetails);

        // Add parameters
        List<Map<String, Object>> params = new ArrayList<>();
        for (Variable param : function.getParameters()) {
            Map<String, Object> p = new HashMap<>();
            p.put("name", param.getName());
            p.put("dataType", param.getDataType().getPathName());
            p.put("storage", param.getVariableStorage().toString());
            // Ordinal is only applicable to Parameters
             if (param instanceof ghidra.program.model.listing.Parameter) { // Check type
                 p.put("ordinal", ((ghidra.program.model.listing.Parameter)param).getOrdinal()); // Cast and call
             }
            params.add(p);
        }
        details.put("parameters", params);

        // Add return type
        details.put("returnType", function.getReturnType().getPathName());

        return details;
     }

    /**
     * Helper method to check for valid symbol names
     *
     * @param name The name to check
     * @return true if valid, false otherwise
     */
     private boolean isValidSymbolName(String name) {
        // Basic check - Ghidra has more complex validation internally
        return name != null && !name.trim().isEmpty() && !name.contains(" ");
     }
} // End of DecompileService
