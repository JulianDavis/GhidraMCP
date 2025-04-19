# GhidraMCP Code Optimization Guide

## Introduction

This guide offers a streamlined approach to optimize the GhidraMCP codebase by reducing cognitive load, minimizing lines of code, and enhancing maintainability. Our focus is on creating a more cohesive codebase through practical solutions rather than theoretical abstractions.

## Core Principles

1. **Reduce Duplication**: Extract common patterns into shared base classes and utilities.
2. **Minimize Parameters**: Use parameter objects for complex operations to reduce method signatures.
3. **Standardize Responses**: Create consistent response formats and error handling.
4. **Focused Components**: Each class should have a clear, single responsibility.
5. **Smart Inheritance**: Use strategic inheritance to reduce boilerplate without over-abstracting.
6. **Practical Type Safety**: Improve type safety in both Java and Python components.


## Java Backend Optimization

### 1. Create a Lean Base Service Class

The current services duplicate common patterns. Create a lightweight base service that eliminates this redundancy:

```java
package com.juliandavis.ghidramcp.core.service;

import java.util.Map;
import com.juliandavis.ghidramcp.api.util.ResponseUtil;
import ghidra.app.plugin.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

public abstract class BaseGhidraService implements Service {
    protected final PluginTool tool;
    protected Program program;
    private final String serviceName;

    protected BaseGhidraService(PluginTool tool, String serviceName) {
        this.tool = tool;
        this.serviceName = serviceName;
    }

    @Override public String getName() { return serviceName; }
    @Override public void initialize(Program program) { this.program = program; }
    @Override public void dispose() { this.program = null; }

    protected boolean isProgramLoaded() {
        return program != null;
    }
    
    protected Map<String, Object> checkProgramLoaded() {
        return isProgramLoaded() ? null : 
            ResponseUtil.createErrorResponse("No program loaded");
    }

    protected Function findFunction(String nameOrAddress) {
        if (!isProgramLoaded() || nameOrAddress == null || nameOrAddress.isEmpty()) {
            return null;
        }
        
        // Try address first
        try {
            Address address = program.getAddressFactory().getAddress(nameOrAddress);
            if (address != null) {
                Function func = program.getFunctionManager().getFunctionAt(address);
                if (func != null) return func;
                
                return program.getFunctionManager().getFunctionContaining(address);
            }
        } catch (Exception e) {
            // Not an address, try name lookup
        }
        
        // Look up by name
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName(true).equals(nameOrAddress) || 
                func.getName().equals(nameOrAddress)) {
                return func;
            }
        }
        
        return null;
    }
}
```

### 2. Create Domain-Specific Service Extensions

Instead of a single base service, create targeted extensions for specific domains:

```java
// For decompiler-related services
public abstract class BaseDecompileService extends BaseGhidraService {
    
    protected BaseDecompileService(PluginTool tool, String serviceName) {
        super(tool, serviceName);
    }
    
    // Shared decompiler setup code
    protected DecompInterface createDecompiler() {
        DecompInterface decompiler = new DecompInterface();
        decompiler.setOptions(new DecompileOptions());
        if (isProgramLoaded()) {
            decompiler.openProgram(program);
        }
        return decompiler;
    }
    
    // Result formatting for decompilation
    protected Map<String, Object> formatDecompileResult(Function function, DecompileResults results) {
        Map<String, Object> response = new HashMap<>();
        
        if (function != null) {
            response.put("function", function.getName(true));
            response.put("address", function.getEntryPoint().toString());
        }
        
        if (results != null && results.decompileCompleted()) {
            response.put("decompiled", results.getDecompiledFunction().getC());
            response.put("success", true);
        } else {
            response.put("success", false);
            response.put("error", results != null ? 
                results.getErrorMessage() : "Unknown decompilation error");
        }
        
        return response;
    }
}

// For memory-related services
public abstract class BaseMemoryService extends BaseGhidraService {
    
    protected BaseMemoryService(PluginTool tool, String serviceName) {
        super(tool, serviceName);
    }
    
    // Common memory address validation
    protected Address validateAddress(String addressStr) {
        if (!isProgramLoaded() || addressStr == null || addressStr.isEmpty()) {
            return null;
        }
        
        try {
            return program.getAddressFactory().getAddress(addressStr);
        } catch (Exception e) {
            return null;
        }
    }
    
    // Standardized memory formatting
    protected Map<String, Object> formatMemoryBytes(String address, byte[] bytes, int length) {
        // Create hex and ascii representation
        StringBuilder hex = new StringBuilder();
        StringBuilder ascii = new StringBuilder();
        
        for (int i = 0; i < length && i < bytes.length; i++) {
            hex.append(String.format("%02x", bytes[i]));
            ascii.append(isPrintable(bytes[i]) ? (char)bytes[i] : '.');
        }
        
        Map<String, Object> data = new HashMap<>();
        data.put("address", address);
        data.put("length", bytes.length);
        data.put("hexValue", hex.toString());
        data.put("asciiValue", ascii.toString());
        
        return data;
    }
    
    private boolean isPrintable(byte b) {
        return b >= 32 && b < 127;
    }
}
```

## Python Bridge Optimization

### 1. Create a Client Class for API Interaction

Centralizing API interaction logic in a client class will reduce duplication and provide a more consistent interface:

```python
from typing import Dict, List, Union, Any, Optional, TypeVar, Generic, Callable, Type, cast
import requests
import json
import logging
from result_objects import *

T = TypeVar('T')

class GhidraClient:
    """
    Client for interacting with the GhidraMCP API.
    
    This class provides a centralized interface for all API requests,
    with standardized error handling and response parsing.
    """
    
    def __init__(self, base_url: str = "http://localhost:8080", timeout: int = 100):
        """
        Initialize the GhidraClient.
        
        Args:
            base_url: The base URL of the GhidraMCP API
            timeout: The request timeout in seconds
        """
        self.base_url = base_url
        self.timeout = timeout
        self.logger = logging.getLogger("GhidraClient")
    
    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform a GET request to the API.
        
        Args:
            endpoint: The API endpoint to call
            params: The query parameters
            
        Returns:
            The parsed response
        """
        if params is None:
            params = {}
            
        url = f"{self.base_url}/{endpoint}"
        
        try:
            self.logger.debug(f"GET request to {url} with params {params}")
            response = requests.get(url, params=params, timeout=self.timeout)
            response.encoding = 'utf-8'
            
            return self._handle_response(response)
            
        except requests.exceptions.Timeout:
            error_msg = f"Request to {url} timed out after {self.timeout}s"
            self.logger.error(error_msg)
            return {
                "status": "error",
                "error": {
                    "message": error_msg,
                    "type": "timeout"
                }
            }
        except requests.exceptions.ConnectionError:
            error_msg = f"Connection error to {url}. Is Ghidra running?"
            self.logger.error(error_msg)
            return {
                "status": "error",
                "error": {
                    "message": error_msg,
                    "type": "connection_error"
                }
            }
        except Exception as e:
            error_msg = f"Request failed: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            return {
                "status": "error",
                "error": {
                    "message": error_msg,
                    "type": "exception",
                    "exception": str(e)
                }
            }
    
    def _handle_response(self, response: requests.Response) -> Dict[str, Any]:
        """
        Handle a response from the API.
        
        Args:
            response: The HTTP response
            
        Returns:
            The parsed response
        """
        if response.ok:
            try:
                # Try to parse as JSON
                json_response = response.json()
                
                # If not already in standardized format, wrap it
                if "status" not in json_response:
                    return {
                        "status": "success",
                        "data": json_response
                    }
                return json_response
            except json.JSONDecodeError:
                # Fall back to text response
                text_response = response.text.strip()
                return {
                    "status": "success",
                    "type": "text_response",
                    "data": {
                        "text": text_response
                    }
                }
        else:
            error_msg = f"Error {response.status_code}: {response.text.strip()}"
            self.logger.error(error_msg)
            return {
                "status": "error",
                "error": {
                    "message": error_msg,
                    "code": response.status_code
                }
            }
    
    def extract_response_data(self, response: Dict[str, Any], result_type: Type[T]) -> Union[T, ErrorResult]:
        """
        Extract data from a standardized response.
        
        Args:
            response: The response dictionary
            result_type: The type to create from the response data
            
        Returns:
            The appropriate result object (success or error)
        """
        # Check if this is already an error
        if isinstance(response, ErrorResult):
            return response
        
        # Check for standardized response with status field
        if "status" in response:
            if response.get("status") == "success":
                # For success responses, use the result_type's from_dict method
                if "data" in response:
                    return result_type.from_dict(response)
                else:
                    self.logger.warning(f"Success response missing 'data' field: {response}")
                    return result_type.from_dict(response)
            else:
                # For error responses, create an ErrorResult
                return ErrorResult.from_dict(response)
        
        # If we can't determine the format, try to parse it as a success result
        try:
            return result_type.from_dict(response)
        except Exception as e:
            self.logger.error(f"Failed to parse response: {e}")
            return ErrorResult.from_string(f"Failed to parse response: {str(e)}")
```

### 2. Implement Type-Safe Service Methods

Implementing type-safe service methods will improve code reliability and developer experience:

```python
class DecompilerService:
    """
    Service for decompiling functions and managing decompiled code.
    """
    
    def __init__(self, client: GhidraClient):
        """
        Initialize the service with a GhidraClient.
        
        Args:
            client: The GhidraClient instance
        """
        self.client = client
        self.logger = logging.getLogger("DecompilerService")
    
    def decompile_function(self, name: str) -> Union[DecompileResult, ErrorResult]:
        """
        Decompile a function by name.
        
        Args:
            name: Name of the function to decompile
            
        Returns:
            DecompileResult with the decompiled code or ErrorResult on failure
        """
        self.logger.info(f"Decompiling function: {name}")
        
        # Make the API request
        response = self.client.post("decompile", name)
        
        # Extract the response data with proper typing
        return self.client.extract_response_data(response, DecompileResult)
    
    def rename_variable(self, function_name: str, variable_name: str, 
                       new_name: str) -> Union[RenameResult, ErrorResult]:
        """
        Rename a variable within a function.
        
        Args:
            function_name: The name of the function containing the variable
            variable_name: The current name of the variable
            new_name: The new name for the variable
            
        Returns:
            RenameResult on success or ErrorResult on failure
        """
        self.logger.info(f"Renaming variable '{variable_name}' to '{new_name}' "
                        f"in function '{function_name}'")
        
        # Prepare the request data
        data = {
            "functionName": function_name,
            "variableName": variable_name,
            "newName": new_name
        }
        
        # Make the API request
        response = self.client.post("decompiler/renameVariable", data)
        
        # Extract the response data with proper typing
        return self.client.extract_response_data(response, RenameResult)
    
    def set_variable_data_type(self, function_name: str, variable_name: str,
                              data_type_name: str) -> Union[DataTypeResult, ErrorResult]:
        """
        Set the data type for a variable within a function.
        
        Args:
            function_name: The name of the function containing the variable
            variable_name: The name of the variable
            data_type_name: The name of the data type to apply
            
        Returns:
            DataTypeResult on success or ErrorResult on failure
        """
        self.logger.info(f"Setting data type of variable '{variable_name}' to "
                        f"'{data_type_name}' in function '{function_name}'")
        
        # Prepare the request data
        data = {
            "functionName": function_name,
            "variableName": variable_name,
            "dataTypeName": data_type_name
        }
        
        # Make the API request
        response = self.client.post("decompiler/setVariableDataType", data)
        
        # Extract the response data with proper typing
        return self.client.extract_response_data(response, DataTypeResult)
```

### 3. Implement a Service Factory

Creating a service factory makes it easy to access all API services through a single entry point:

```python
class GhidraServiceFactory:
    """
    Factory for creating service instances.
    
    This factory provides access to all GhidraMCP services 
    through a single entry point.
    """
    
    def __init__(self, base_url: str = "http://localhost:8080", timeout: int = 100):
        """
        Initialize the service factory.
        
        Args:
            base_url: The base URL of the GhidraMCP API
            timeout: The request timeout in seconds
        """
        self.client = GhidraClient(base_url, timeout)
        self._decompiler = None
        self._emulator = None
        self._memory = None
        self._function = None
        
    @property
    def decompiler(self) -> DecompilerService:
        """Get the decompiler service."""
        if self._decompiler is None:
            self._decompiler = DecompilerService(self.client)
        return self._decompiler
    
    @property
    def emulator(self) -> EmulatorService:
        """Get the emulator service."""
        if self._emulator is None:
            self._emulator = EmulatorService(self.client)
        return self._emulator
    
    @property
    def memory(self) -> MemoryService:
        """Get the memory service."""
        if self._memory is None:
            self._memory = MemoryService(self.client)
        return self._memory
    
    @property
    def function(self) -> FunctionService:
        """Get the function service."""
        if self._function is None:
            self._function = FunctionService(self.client)
        return self._function
```

### 4. Use Decorator Pattern for Tool Functions

Using decorators for tool functions can significantly improve error handling and logging:

```python
def api_tool(result_type: Type[T]):
    """
    Decorator for API tool functions.
    
    This decorator provides consistent error handling and logging
    for all tool functions.
    
    Args:
        result_type: The result type to return on success
        
    Returns:
        A decorator function
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Get the function name for logging
            func_name = func.__name__
            
            # Log the function call
            logger.debug(f"Calling {func_name} with args={args}, kwargs={kwargs}")
            
            try:
                # Call the original function
                result = func(*args, **kwargs)
                
                # Handle errors
                if isinstance(result, dict) and "status" in result and result.get("status") == "error":
                    error_msg = result.get("error", {}).get("message", "Unknown error")
                    logger.error(f"Error in {func_name}: {error_msg}")
                    return ErrorResult.from_dict(result)
                
                # Extract data with proper typing
                if isinstance(result, dict):
                    # Check for standardized response format
                    if "status" in result and result.get("status") == "success" and "data" in result:
                        data = result.get("data", {})
                        return result_type.from_dict(data)
                    
                    # Try to parse as a direct result
                    return result_type.from_dict(result)
                
                # Handle direct object returns
                if isinstance(result, result_type):
                    return result
                
                # Handle ErrorResult
                if isinstance(result, ErrorResult):
                    return result
                
                # Default case: convert to string and return error
                logger.error(f"Unexpected result type from {func_name}: {type(result)}")
                return ErrorResult.from_string(f"Unexpected result type: {type(result)}")
                
            except Exception as e:
                # Log and return any exceptions
                logger.error(f"Exception in {func_name}: {str(e)}", exc_info=True)
                return ErrorResult.from_string(f"Exception: {str(e)}")
        
        return wrapper
    
    return decorator
```

### 5. Parameter Objects for Complex Operations

Replace long parameter lists with immutable parameter objects:

```java
// Function prototype parameter object
public class FunctionPrototypeParams {
    private final String functionName;
    private final String returnType;
    private final List<ParameterInfo> parameters;
    private final String callingConvention;
    private final String renameOption;
    private final boolean isVariadic;
    
    // Parameter info nested class
    public static class ParameterInfo {
        private final String name;
        private final String type;
        private final String storage;
        
        public ParameterInfo(String name, String type, String storage) {
            this.name = name;
            this.type = type;
            this.storage = storage;
        }
        
        // Getters
        public String getName() { return name; }
        public String getType() { return type; }
        public String getStorage() { return storage; }
    }
    
    // Static factory for creating from a request map
    public static FunctionPrototypeParams from(Map<String, Object> map) {
        String name = (String) map.get("functionName");
        String returnType = (String) map.get("returnType");
        String convention = (String) map.get("callingConvention");
        String renameOpt = (String) map.getOrDefault("rename_option", "RENAME_IF_DEFAULT");
        boolean variadic = Boolean.parseBoolean(String.valueOf(
                map.getOrDefault("is_variadic", "false")));
        
        List<ParameterInfo> params = new ArrayList<>();
        Object paramsObj = map.get("parameters");
        
        if (paramsObj instanceof List) {
            for (Object paramObj : (List<?>) paramsObj) {
                if (paramObj instanceof Map) {
                    Map<?, ?> paramMap = (Map<?, ?>) paramObj;
                    params.add(new ParameterInfo(
                        (String) paramMap.get("name"),
                        (String) paramMap.get("type"),
                        (String) paramMap.get("storage")
                    ));
                }
            }
        }
        
        return new FunctionPrototypeParams(name, returnType, params, 
            convention, renameOpt, variadic);
    }
    
    // Constructor
    public FunctionPrototypeParams(String functionName, String returnType, 
                                   List<ParameterInfo> parameters,
                                   String callingConvention, 
                                   String renameOption, boolean isVariadic) {
        this.functionName = functionName;
        this.returnType = returnType;
        this.parameters = parameters != null ? parameters : new ArrayList<>();
        this.callingConvention = callingConvention;
        this.renameOption = renameOption != null ? renameOption : "RENAME_IF_DEFAULT";
        this.isVariadic = isVariadic;
    }
    
    // Validation
    public Optional<String> validate() {
        if (functionName == null || functionName.isEmpty()) {
            return Optional.of("Function name is required");
        }
        
        if (returnType == null || returnType.isEmpty()) {
            return Optional.of("Return type is required");
        }
        
        return Optional.empty();
    }
    
    // Getters
    public String getFunctionName() { return functionName; }
    public String getReturnType() { return returnType; }
    public List<ParameterInfo> getParameters() { return parameters; }
    public String getCallingConvention() { return callingConvention; }
    public String getRenameOption() { return renameOption; }
    public boolean isVariadic() { return isVariadic; }
}
```

The service implementation also becomes simpler:

```java
// Before: Complex method signature
public Map<String, Object> setFunctionPrototype(String functionName, 
                                             String returnType, 
                                             List<Map<String, String>> parameters, 
                                             String callingConvention, 
                                             String renameOptionStr, 
                                             boolean isVariadic) {
    // Long implementation with repeated parameter validation
    // ...
}

// After: Clean method signature
public Map<String, Object> setFunctionPrototype(FunctionPrototypeParams params) {
    // Implementation that uses the validated parameter object
    // ...
}
```

## Implementation Approach

To implement these optimizations effectively, follow this phased approach:

### Phase 1: Create Base Classes

1. **Create Base Service Classes**
   - Implement `BaseGhidraService` with common functionality
   - Create specialized base classes for related services (e.g., `BaseDecompileService`)
   - Implement `ResponseUtil` for standardized responses

2. **Create Base HTTP Handler Class**
   - Enhance `BaseHttpHandler` with improved request/response handling
   - Implement structured error handling
   - Add standardized validation methods

### Phase 2: Refactor Service Layer

1. **Create Parameter Objects**
   - Identify services with complex parameter requirements
   - Create immutable parameter classes with validation
   - Update service methods to use parameter objects

2. **Enhance Service Implementations**
   - Refactor existing services to extend from appropriate base classes
   - Remove duplicated code and centralize common functionality
   - Add comprehensive documentation

### Phase 3: Enhance Python Bridge

1. **Create Client Class**
   - Implement `GhidraClient` for standardized API interaction
   - Create typed service classes for each API category
   - Implement consistent error handling

2. **Refactor Tool Functions**
   - Create decorator for enhanced error handling
   - Convert result handling to use typed objects
   - Update documentation and type hints

### Phase 4: Reorganize Package Structure

1. **Create New Package Structure**
   - Create logical groupings for services and handlers
   - Organize by functionality rather than technical concerns
   - Create proper layering between components

2. **Update References**
   - Update import statements throughout the codebase
   - Fix any affected dependencies
   - Update documentation to reflect new structure

### Phase 5: Testing and Validation

1. **Create Test Cases**
   - Create comprehensive test cases for each service
   - Test error handling and edge cases
   - Validate parameter validation

2. **Validate Functionality**
   - Ensure all existing functionality continues to work
   - Compare response formats for compatibility
   - Validate error handling and logging

## Implementation Plan

For maximum impact with minimal effort, implement these changes in phases:

### Phase 1: Base Components (1-2 days)
1. Create `BaseGhidraService` with core utility methods
2. Implement domain-specific service bases (Memory, Decompiler, etc.)
3. Set up `ResponseUtil` for standardized responses

### Phase 2: HTTP Layer Optimization (1-2 days)
1. Enhance `BaseHttpHandler` with functional processing
2. Create the validation exception hierarchy
3. Add the parameter parsing and validation utilities

### Phase 3: Parameter Objects (2-3 days)
1. Identify the services with the most complex parameters
2. Create parameter objects with validation for these services
3. Update service methods to use parameter objects

### Phase 4: Python Bridge (2-3 days)
1. Create the `GhidraClient` class
2. Implement service-specific wrapper classes
3. Add decorator pattern for tool functions

### Phase 5: Package Restructuring (1 day)
1. Create the new package structure
2. Move classes to appropriate packages
3. Update imports and fix any issues

## Summary

These optimization strategies will significantly reduce your codebase size and complexity:

1. **~40% Less Code**: By using base classes and parameter objects, you'll eliminate thousands of lines of duplicate code.

2. **Cleaner APIs**: Parameter objects with validation create self-documenting interfaces with better error messages.

3. **Simplified Reasoning**: Functional request processing reduces the cognitive load of reasoning about request handling.

4. **Improved Type Safety**: Both Java and Python components will have better type safety, catching errors earlier.

5. **Better Maintainability**: Clear organization by domain rather than technical concerns makes future changes easier.

Following this plan will give you a codebase that's easier to understand, extend, and maintain, without compromising functionality.
