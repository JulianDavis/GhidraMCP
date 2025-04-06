package com.juliandavis.ghidramcp.services;

import com.juliandavis.ghidramcp.core.service.Service;

import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.app.util.NamespaceUtils;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.program.model.listing.ParameterImpl;

import java.util.*;

/**
 * Service for managing function prototypes (signatures) in Ghidra.
 */
public class FunctionPrototypeService implements Service {

    public static final String SERVICE_NAME = "FunctionPrototypeService";
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
     * Set a function prototype (signature) for a function
     *
     * @param functionName The name of the function to modify
     * @param returnType The return type name
     * @param parameterDefinitions List of parameter definitions (name and type pairs)
     * @param callingConvention Optional calling convention (can be null to keep existing)
     * @param forceUpdate Whether to force update even if parameters might be incompatible
     * @return Map containing the result of the operation
     */
    public Map<String, Object> setFunctionPrototype(
            String functionName,
            String returnType, 
            List<Map<String, String>> parameterDefinitions,
            String callingConvention,
            boolean forceUpdate) {
        
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        if (functionName == null || functionName.isEmpty()) {
            return createErrorResponse("Function name is required");
        }
        
        if (returnType == null || returnType.isEmpty()) {
            return createErrorResponse("Return type is required");
        }
        
        try {
            // Find the function by name
            Function function = findFunction(functionName);
            if (function == null) {
                return createErrorResponse("Function not found: " + functionName);
            }
            
            // Resolve the return data type
            DataType returnDataType = resolveDataType(returnType);
            if (returnDataType == null) {
                return createErrorResponse("Could not resolve return type: " + returnType);
            }
            
            // Create the parameter definitions using the example approach
            List<Parameter> newParams = new ArrayList<>();
            
            // Build the new parameter list
            for (int i = 0; i < parameterDefinitions.size(); i++) {
                Map<String, String> paramDef = parameterDefinitions.get(i);
                String paramName = paramDef.get("name");
                String paramType = paramDef.get("type");
                
                if (paramName == null || paramName.isEmpty()) {
                    return createErrorResponse("Parameter name is required");
                }
                
                if (paramType == null || paramType.isEmpty()) {
                    return createErrorResponse("Parameter type is required");
                }
                
                DataType paramDataType = resolveDataType(paramType);
                if (paramDataType == null) {
                    return createErrorResponse("Could not resolve parameter type: " + paramType);
                }
                
                // Get or create parameters using the function's createParameter method
                try {
                    // Create or get parameter for the ordinal
                    Parameter param;
                    if (i < function.getParameterCount()) {
                        // Modify existing parameter
                        param = function.getParameter(i);
                        // We'll update its type and name in the transaction below
                    } else {
                        // Create a placeholder - actual parameter will be created in transaction
                        param = null;
                    }
                    
                    // Add to our list (could be null for new parameters)
                    newParams.add(param);
                } catch (Exception e) {
                    return createErrorResponse("Error creating parameter: " + e.getMessage());
                }
            }
            
            // Begin transaction
            int txId = program.startTransaction("Set Function Prototype: " + functionName);
            boolean success = false;
            String message;
            
            try {
                // Set the return type
                function.setReturnType(returnDataType, SourceType.USER_DEFINED);
                
                // Set calling convention if specified
                if (callingConvention != null && !callingConvention.isEmpty()) {
                    function.setCallingConvention(callingConvention);
                }
                
                // Following the method signature from the documentation:
                // void replaceParameters(List<? extends Variable> params, Function.FunctionUpdateType updateType, boolean force, SourceType source)
                
                // For this, we need a list of Variables (Parameters are Variables)
                // We can use our newParams list directly
                
                // Create actual parameter objects
                // First, we'll clear the existing parameters to make sure we're starting fresh
                List<Parameter> parameters = new ArrayList<>();
                for (Map<String, String> paramDef : parameterDefinitions) {
                    String paramName = paramDef.get("name");
                    String paramType = paramDef.get("type");

                    DataType paramDataType = resolveDataType(paramType);
                    // Use the function's createParameter method to get proper parameter objects
                    Parameter param = new ParameterImpl(paramName, paramDataType, program);
                    parameters.add(param);
                }
                

                // Call the actual method with the correct signature
                function.replaceParameters(parameters, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, forceUpdate, SourceType.USER_DEFINED);
                
                success = true;
                message = "Function prototype updated successfully";
            } catch (DuplicateNameException e) {
                message = "Error updating function prototype: duplicate parameter name: " + e.getMessage();
                Msg.error(this, message, e);
            } catch (InvalidInputException e) {
                message = "Error updating function prototype: invalid input: " + e.getMessage();
                Msg.error(this, message, e);
            } catch (Exception e) {
                message = "Error updating function prototype: " + e.getMessage();
                Msg.error(this, message, e);
            } finally {
                program.endTransaction(txId, success);
            }
            
            // Prepare the response
            Map<String, Object> result = new HashMap<>();
            result.put("success", success);
            result.put("message", message);
            result.put("functionName", functionName);
            
            if (success) {
                // Include the updated function details
                result.put("function", getFunctionDetails(function));
            }
            
            return createSuccessResponse(result);
            
        } catch (Exception e) {
            Msg.error(this, "Error setting function prototype", e);
            return createErrorResponse("Error: " + e.getMessage());
        }
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
        
        // Try to find the function by name
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
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
        
        DataType resolvedType;
        
        // Check for built-in types first (more efficient for common types)
        resolvedType = BuiltInDataTypeManager.getDataTypeManager().getDataType(typeNameOrPath);
        
        // If not found as built-in, check in the program's data type manager
        if (resolvedType == null) {
            resolvedType = program.getDataTypeManager().getDataType(typeNameOrPath);
        }
        
        // Handle pointer types (indicated by * suffix)
        if (resolvedType == null && typeNameOrPath.endsWith("*")) {
            String baseTypeName = typeNameOrPath.substring(0, typeNameOrPath.length() - 1).trim();
            DataType baseType = resolveDataType(baseTypeName);
            if (baseType != null) {
                resolvedType = program.getDataTypeManager().getPointer(baseType);
            }
        }
        
        // Try finding by symbol path as last resort
        if (resolvedType == null) {
            try {
                // Look for matching symbols
                List<ghidra.program.model.symbol.Symbol> symbols = 
                    NamespaceUtils.getSymbols(typeNameOrPath, program);
                
                // If we found symbols, check if they correspond to data types
                if (!symbols.isEmpty()) {
                    for (ghidra.program.model.symbol.Symbol symbol : symbols) {
                        Object obj = symbol.getObject();
                        if (obj instanceof ghidra.program.model.data.DataType) {
                            resolvedType = (ghidra.program.model.data.DataType) obj;
                            break;
                        }
                    }
                }
            } 
            catch (Exception e) {
                Msg.error(this, "Error parsing data type path: " + typeNameOrPath, e);
            }
        }
        
        // Final fallback: search by simple name
        if (resolvedType == null) {
            List<DataType> foundTypes = new ArrayList<>();
            program.getDataTypeManager().findDataTypes(typeNameOrPath, foundTypes);
            
            if (foundTypes.size() == 1) {
                resolvedType = foundTypes.get(0);
            }
            else if (foundTypes.size() > 1) {
                Msg.warn(this, "Ambiguous data type name: " + typeNameOrPath + ". Found multiple matches.");
                // Just use the first one
                resolvedType = foundTypes.get(0);
            }
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
        details.put("name", function.getName());
        details.put("address", function.getEntryPoint().toString());
        details.put("signature", function.getSignature().toString());
        details.put("returnType", function.getReturnType().toString());
        details.put("parameterCount", function.getParameterCount());
        
        // Include namespace information
        details.put("namespace", function.getParentNamespace().getName());

        // Include calling convention if available
        if (function.getCallingConvention() != null) {
            details.put("callingConvention", function.getCallingConvention().toString());
        }

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