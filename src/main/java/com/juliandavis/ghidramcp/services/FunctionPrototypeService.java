package com.juliandavis.ghidramcp.services;

import com.juliandavis.ghidramcp.core.service.Service;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.FunctionRenameOption; // Import needed for constructor
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;
import ghidra.program.model.listing.VariableStorage; // Needed for getFunctionDetails
// ParameterImpl is not needed for the new approach
import ghidra.program.model.lang.ProgramArchitecture;
// import ghidra.program.model.listing.ParameterImpl;
import ghidra.util.task.ConsoleTaskMonitor; // Needed for running the command
import java.util.*;

/**
 * Service for managing function prototypes (signatures) in Ghidra.
 * Uses direct API calls for setting convention/return type and manual parameter manipulation for custom storage.
 */
public class FunctionPrototypeService implements Service {

    public static final String SERVICE_NAME = "FunctionPrototypeService";
    private Program program;
    private ProgramArchitecture programArch; // Store architecture
    private PluginTool tool;

    // Constructor now takes PluginTool
    public FunctionPrototypeService(PluginTool tool) {
        this.tool = tool;
    }

    @Override
    public String getName() {
        return SERVICE_NAME;
    }

    @Override
    public void initialize(Program program) {
        this.program = program;
        if (program != null) {
            // Get architecture once during initialization
            this.programArch = program.getDataTypeManager().getProgramArchitecture();
        } else {
            this.programArch = null;
        }
    }

    @Override
    public void dispose() {
        this.program = null;
        this.programArch = null;
    }

    /**
     * Set a function prototype (signature) for a function using a hybrid approach.
     *
     * @param functionName The name of the function to modify
     * @param returnType The return type name
     * @param parameterDefinitions List of parameter definitions (name, type, storage)
     * @param callingConvention Optional calling convention name (e.g., "__thiscall", "__stdcall")
     * @param renameOption Controls function renaming ("RENAME", "RENAME_IF_DEFAULT", "NO_CHANGE"). Defaults to RENAME_IF_DEFAULT.
     * @return Map containing the result of the operation
     */
    public Map<String, Object> setFunctionPrototype(
            String functionName,
            String returnType,
            List<Map<String, String>> parameterDefinitions,
            String callingConvention,
            String renameOptionStr) {
        Msg.info(this, "setFunctionPrototype called for: " + functionName);
        Msg.info(this, "  Return Type: " + returnType);
        Msg.info(this, "  Parameters: " + parameterDefinitions);
        Msg.info(this, "  Calling Convention: " + callingConvention);
        Msg.info(this, "  Rename Option: " + renameOptionStr);

        if (program == null || programArch == null) {
            return createErrorResponse("No program loaded or architecture not available");
        }
        if (functionName == null || functionName.isEmpty()) {
            return createErrorResponse("Function name is required");
        }
        if (returnType == null || returnType.isEmpty()) {
            return createErrorResponse("Return type is required");
        }

        Function function = null;

        try {
            function = findFunction(functionName);
            if (function == null) {
                Msg.error(this, "Function not found: " + functionName);
                return createErrorResponse("Function not found: " + functionName);
            }

            DataType returnDataType = resolveDataType(returnType);
            if (returnDataType == null) {
                Msg.error(this, "Could not resolve return type: " + returnType);
                return createErrorResponse("Could not resolve return type: " + returnType);
            }
            Msg.info(this, "Resolved return type: " + returnDataType.getName());

            // --- ApplyFunctionSignatureCmd Approach (using tool.execute) ---
            boolean success = false;
            String message = "An unexpected error occurred."; // Default error message

            try {
                 // Transaction and monitor handled by tool.execute
                 DataTypeManager dtm = program.getDataTypeManager();

                 // 1. Resolve Parameter Data Types and Create Parameter Definitions (Reverted: No filtering)
                 List<ParameterDefinition> params = new ArrayList<>();
                 for (Map<String, String> paramDef : parameterDefinitions) {
                     String paramName = paramDef.get("name");
                     String paramType = paramDef.get("type");

                     if (paramName == null || paramName.isEmpty()) {
                          throw new InvalidInputException("Parameter name is required.");
                     }
                      if (paramType == null || paramType.isEmpty()) {
                          throw new InvalidInputException("Parameter type is required for parameter: " + paramName);
                     }

                     DataType paramDataType = resolveDataType(paramType);
                     if (paramDataType == null) {
                         Msg.error(this, "Could not resolve parameter type: " + paramType + " for parameter: " + paramName);
                         throw new InvalidInputException("Could not resolve parameter type: " + paramType + " for parameter: " + paramName);
                     }
                     params.add(new ParameterDefinitionImpl(paramName, paramDataType, null));
                     Msg.info(this, "  Resolved param '" + paramName + "' type: " + paramDataType.getName()); // Moved inside loop
                 }

                 // 2. Create Function Definition Data Type
                 CategoryPath categoryPath = dtm.getRootCategory().getCategoryPath();
                 // Use a distinct name for the signature to avoid potential conflicts if the function name itself is being changed
                 String signatureName = function.getName() + "_prototype";
                 Msg.info(this, "Prepared ParameterDefinition list (size " + params.size() + "): " + params);
                 FunctionDefinitionDataType newSignature = new FunctionDefinitionDataType(categoryPath, signatureName, dtm);

                 // 3. Set Return Type, Parameters, and Calling Convention
                 newSignature.setReturnType(returnDataType);
                 newSignature.setArguments(params.toArray(new ParameterDefinition[0])); // Use the full parameter list

                 // 3. Determine and *explicitly set* the calling convention on the new signature
                 String targetCallingConvention = callingConvention;
                 if (targetCallingConvention == null || targetCallingConvention.isEmpty()) {
                     // If not specified in request, use the function's current convention
                     targetCallingConvention = function.getCallingConventionName();
                 }
                 // Ensure we don't try to set a null/empty convention name
                 if (targetCallingConvention != null && !targetCallingConvention.isEmpty() && !"unknown".equals(targetCallingConvention)) { // Use string literal
                      try {
                           newSignature.setCallingConvention(targetCallingConvention);
                           Msg.info(this, "Explicitly set calling convention '" + targetCallingConvention + "' on FunctionDefinitionDataType.");
                      } catch (InvalidInputException e) {
                           // This might happen if the provided name is invalid
                           // Corrected Exception handling: Just pass the message string
                           throw new InvalidInputException("Invalid calling convention name provided: " + targetCallingConvention);
                      }
                 } else {
                      Msg.warn(this, "No valid calling convention specified or found for function; signature will use default.");
                      // Let newSignature keep its default convention if none is specified or found
                 }
                 Msg.info(this, "Configured newSignature: " + newSignature.getPrototypeString());

                 // 4. Determine Rename Option based on renameOptionStr input
                 FunctionRenameOption renameOption;
                 if (renameOptionStr == null || renameOptionStr.isEmpty() || "RENAME_IF_DEFAULT".equalsIgnoreCase(renameOptionStr)) {
                     renameOption = FunctionRenameOption.RENAME_IF_DEFAULT;
                 } else if ("RENAME".equalsIgnoreCase(renameOptionStr)) {
                     renameOption = FunctionRenameOption.RENAME;
                 } else if ("NO_CHANGE".equalsIgnoreCase(renameOptionStr)) {
                     renameOption = FunctionRenameOption.NO_CHANGE;
                 } else {
                     throw new InvalidInputException("Invalid renameOption specified: " + renameOptionStr +
                             ". Must be one of RENAME, RENAME_IF_DEFAULT, NO_CHANGE.");
                 }
                 Msg.info(this, "Determined renameOption: " + renameOption);

                 // 5. Create and Apply the Command using the non-deprecated constructor
                 ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                         function.getEntryPoint(),
                         newSignature,
                         SourceType.USER_DEFINED,
                         true, // preserveCallingConvention - TRY TRUE: Preserve if function already has it
                         false, // applyEmptyComposites - default to false
                         DataTypeConflictHandler.DEFAULT_HANDLER, // conflictHandler - use default
                         renameOption // functionRenameOption - based on renameOptionStr
                 );
                 Msg.info(this, "Created ApplyFunctionSignatureCmd. Preserving convention: " + true + ", Rename option: " + renameOption);

                 // Execute the command using PluginTool, which handles transactions and monitoring
                 Msg.info(this, "Executing command via tool.execute...");
                 success = tool.execute(cmd, program); // Pass program as the second argument
                 Msg.info(this, "tool.execute completed. Success: " + success);

                 if (success) {
                     message = "Function prototype updated successfully using ApplyFunctionSignatureCmd.";
                 } else {
                     // cmd.getStatusMsg() might provide more details on failure
                     String cmdStatus = cmd.getStatusMsg();
                     message = "Failed to apply function signature command.";
                     if (cmdStatus != null && !cmdStatus.isEmpty()) {
                         message += " Reason: " + cmdStatus;
                     }
                     Msg.error(this, message + " (cmd status: " + cmdStatus + ")");
                 }

            } catch (InvalidInputException e) { // Catch errors during setup (before command execution)
                 message = "Error preparing function signature update: " + e.getMessage();
                 Msg.error(this, message, e);
                 success = false;
                 // No transaction to abort here as tool.execute wasn't reached
            } catch (Exception e) { // Catch other unexpected exceptions
                 message = "Unexpected error updating function prototype: " + e.getMessage();
                 Msg.error(this, message, e);
                 success = false;
                 // No transaction to abort here
            }
            // --- End ApplyFunctionSignatureCmd Approach ---

            // Construct the final response outside the try-catch for the command execution
            Map<String, Object> resultData = new HashMap<>();
            resultData.put("functionName", functionName);
            resultData.put("message", message); // Include the final message (success or error)

            // Refresh function details only on success
            Function updatedFunction = findFunction(functionName); // Attempt to find function regardless of success
            if (updatedFunction != null) {
                 resultData.put("function", getFunctionDetails(updatedFunction));
            } else if (success) {
                 // Only warn if the command succeeded but we can't find the function afterwards
                 Msg.warn(this, "Function could not be found after successful signature update: " + functionName);
            }

            if (success) {
                 return createSuccessResponse(resultData);
            } else {
                 // Error occurred, return error response with the message set in the catch blocks
                 Msg.info(this, "Returning error response: " + message);
                 return createErrorResponse(message);
            }

        } catch (Exception e) { // Catch errors during initial setup (e.g., finding function, resolving return type)
            Msg.error(this, "Error setting function prototype (initial setup)", e);
            // Ensure a transaction isn't left open if an error occurs very early
            // (No transaction should be active here as txId is initialized to -1)
            Msg.error(this, "Outer catch block: " + e.getMessage(), e);
            return createErrorResponse("Setup Error: " + e.getMessage());
        }
        // This part should now be unreachable due to returns in the blocks above
    }

    /**
     * Find a function by name
     *
     * @param name The function name to search for
     * @return The function if found, null otherwise
     */
    private Function findFunction(String name) {
        if (program == null || name == null || name.isEmpty()) {
            return null;
        }
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            // Consider matching full name with namespace if needed later
            if (func.getName(true).equals(name) || func.getName().equals(name)) {
                return func;
            }
        }
        return null;
    }

    /**
     * Resolve a data type by name or path
     *
     * @param typeNameOrPath The data type name or path
     * @return The resolved data type, or null if not found
     */
    private DataType resolveDataType(String typeNameOrPath) {
        if (program == null || typeNameOrPath == null || typeNameOrPath.isEmpty()) {
            return null;
        }
        DataTypeManager dtm = program.getDataTypeManager();

        // 1. Handle Pointers Recursively
        if (typeNameOrPath.endsWith("*")) {
            String baseTypeName = typeNameOrPath.substring(0, typeNameOrPath.length() - 1).trim();
            if (baseTypeName.isEmpty()) {
                 Msg.error(this, "Invalid pointer type specified: " + typeNameOrPath);
                 return null; // Cannot have a pointer to nothing
            }
            DataType baseType = resolveDataType(baseTypeName); // Recursive call
            if (baseType != null) {
                // Use PointerDataType constructor for consistency with Python example
                return new PointerDataType(baseType, dtm);
            } else {
                Msg.warn(this, "Could not resolve base type '" + baseTypeName + "' for pointer type '" + typeNameOrPath + "'");
                return null; // Base type not found
            }
        }

        // 2. Handle Non-Pointers: Prioritize Program DTM (including paths)
        DataType resolvedType = dtm.getDataType(typeNameOrPath);

        // 3. Fallback: Search Program DTM by simple name (if not found by path/name directly)
        if (resolvedType == null) {
            List<DataType> foundTypes = new ArrayList<>();
            // Use findDataTypes which searches by name across categories
            dtm.findDataTypes(typeNameOrPath, foundTypes);
            if (foundTypes.size() == 1) {
                resolvedType = foundTypes.get(0);
                 Msg.info(this, "Resolved ambiguous type name '" + typeNameOrPath + "' to '" + resolvedType.getPathName() + "' using findDataTypes.");
            } else if (foundTypes.size() > 1) {
                // Log ambiguity but maybe still try the first one? Or error out?
                // Let's log and return the first for now, consistent with previous logic.
                resolvedType = foundTypes.get(0);
                Msg.warn(this, "Ambiguous data type name: '" + typeNameOrPath + "'. Found " + foundTypes.size() + " matches. Using first: " + resolvedType.getPathName());
                // Consider throwing an error or returning null for ambiguity if strictness is desired.
            }
        }

        // 4. Fallback: Check BuiltIn Types (should usually be found by dtm.getDataType already)
        if (resolvedType == null) {
            resolvedType = BuiltInDataTypeManager.getDataTypeManager().getDataType(typeNameOrPath);
             if (resolvedType != null) {
                 Msg.info(this, "Resolved type '" + typeNameOrPath + "' as a BuiltIn type.");
             }
        }

        // 5. Final Check and Log if Not Found
        if (resolvedType == null) {
             Msg.warn(this, "Could not resolve data type: " + typeNameOrPath);
        }

        return resolvedType;
    }

    /**
     * Get detailed information about a function
     *
     * @param function The function to get details for
     * @return Map containing function details
     */
    private Map<String, Object> getFunctionDetails(Function function) {
        Map<String, Object> details = new HashMap<>();
        details.put("name", function.getName(true)); // Use true for full namespace
        details.put("address", function.getEntryPoint().toString());
        details.put("signature", function.getSignature().toString());
        details.put("returnType", function.getReturnType().getDisplayName()); // Use DisplayName
        details.put("parameterCount", function.getParameterCount());
        details.put("namespace", function.getParentNamespace().getName(true)); // Use true for full namespace
        if (function.getCallingConvention() != null) {
            details.put("callingConvention", function.getCallingConvention().getName());
        }
        List<Map<String, Object>> parameters = new ArrayList<>();
        for (Parameter param : function.getParameters()) {
            Map<String, Object> paramDetails = new HashMap<>();
            paramDetails.put("name", param.getName());
            paramDetails.put("dataType", param.getDataType().getDisplayName()); // Use DisplayName
            paramDetails.put("ordinal", param.getOrdinal());
            // Storage details are less relevant with ApplyFunctionSignatureCmd managing it
            // try {
            //      paramDetails.put("storage", param.getVariableStorage().toString());
            // } catch (InvalidInputException e) {
            //      paramDetails.put("storage", "invalid");
            // }
            try {
                VariableStorage storage = param.getVariableStorage();
                if (storage != null && storage.isValid()) {
                    paramDetails.put("storage", storage.toString());
                } else {
                    paramDetails.put("storage", "default/invalid");
                }
            } catch (Exception e) { // Catch any exception during storage retrieval
                 Msg.warn(this, "Error retrieving storage for parameter " + param.getName() + ": " + e.getMessage());
                 paramDetails.put("storage", "error retrieving");
            }
            parameters.add(paramDetails);
        }
        details.put("parameters", parameters);
        return details;
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
        response.put("status", "error");
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
        response.put("status", "success");
        response.put("data", data);
        return response;
    }

    /**
     * Apply function data types to a function at the specified address.
     * Uses Ghidra's ApplyFunctionDataTypesCmd to automatically propagate defined types.
     *
     * @param functionAddressStr The address of the function as a string (e.g., "0x1400")
     * @param alwaysReplace Whether to always replace existing function signatures (default: true)
     * @param createBookmarks Whether to create bookmarks when a function signature is applied (default: true)
     * @return Map containing the result of the operation
     */
    public Map<String, Object> applyFunctionDataTypes(
            String functionAddressStr,
            boolean alwaysReplace,
            boolean createBookmarks) {
        
        Msg.info(this, "applyFunctionDataTypes called for address: " + functionAddressStr);
        
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        if (functionAddressStr == null || functionAddressStr.isEmpty()) {
            return createErrorResponse("Function address is required");
        }
        
        try {
            // Parse the address
            ghidra.program.model.address.Address functionAddress = program.getAddressFactory().getAddress(functionAddressStr);
            if (functionAddress == null) {
                return createErrorResponse("Invalid address format: " + functionAddressStr);
            }
            
            // Find the function at the specified address
            Function function = program.getFunctionManager().getFunctionAt(functionAddress);
            if (function == null) {
                return createErrorResponse("No function found at address: " + functionAddressStr);
            }
            
            // Create an address set from the function's entry point
            ghidra.program.model.address.AddressSet addressSet = new ghidra.program.model.address.AddressSet(functionAddress);
            
            // Create the command using the program's data type manager
            ghidra.app.cmd.function.ApplyFunctionDataTypesCmd cmd = 
                new ghidra.app.cmd.function.ApplyFunctionDataTypesCmd(
                    program.getDataTypeManager().getRootCategory(), // Use the root category to search all data types
                    addressSet,
                    ghidra.program.model.symbol.SourceType.USER_DEFINED,
                    alwaysReplace,
                    createBookmarks
                );
            
            // Execute the command
            boolean success = tool.execute(cmd, program);
            
            // Prepare response
            Map<String, Object> resultData = new HashMap<>();
            resultData.put("address", functionAddressStr);
            resultData.put("functionName", function.getName());
            
            if (success) {
                // Get updated function details after command execution
                Function updatedFunction = program.getFunctionManager().getFunctionAt(functionAddress);
                resultData.put("success", true);
                resultData.put("message", "Successfully applied function data types");
                resultData.put("function", getFunctionDetails(updatedFunction));
                return createSuccessResponse(resultData);
            } else {
                // Command failed
                String statusMsg = cmd.getStatusMsg();
                resultData.put("success", false);
                resultData.put("message", "Failed to apply function data types: " + 
                    (statusMsg != null ? statusMsg : "Unknown error"));
                return createErrorResponse(resultData.get("message").toString());
            }
            
        } catch (Exception e) {
            Msg.error(this, "Error applying function data types", e);
            return createErrorResponse("Error: " + e.getMessage());
        }
    }
}
