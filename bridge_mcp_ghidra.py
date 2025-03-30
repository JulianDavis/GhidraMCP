from mcp.server.fastmcp import FastMCP
import requests
import json
import logging
from typing import Dict, List, Union, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("GhidraMCP-Bridge")

# Connection settings
ghidra_server_url = "http://localhost:8080"
DEFAULT_TIMEOUT = 100  # Increased timeout for large binaries

mcp = FastMCP("ghidra-mcp", request_timeout=300)  # 5 minute timeout for MCP requests

# ----------------------------------------------------------------------------------
# Emulator functions
# ----------------------------------------------------------------------------------

@mcp.tool()
def emulator_initialize(address: str, write_tracking: bool = True) -> Dict[str, Any]:
    """
    Initialize an emulator session at the specified address.
    
    Args:
        address: The address to start emulation from (e.g., "0x1400")
        write_tracking: Whether to enable memory write tracking
        
    Returns:
        Dictionary containing session ID and status information
    """
    response = safe_post("emulator/initialize", {
        "address": address,
        "writeTracking": str(write_tracking).lower()
    })
    
    if isinstance(response, dict):
        return response
    else:
        # Convert string response to dict for consistency
        return {
            "success": False,
            "error": response if isinstance(response, str) else "Unknown error"
        }

@mcp.tool()
def emulator_step() -> Dict[str, Any]:
    """
    Step the emulator forward by one instruction.
    
    Returns:
        Dictionary containing the result of the step operation, including:
        - previousPC: The program counter value before stepping
        - newPC: The program counter value after stepping
        - instruction: The executed instruction (if available)
    """
    response = safe_get("emulator/step")
    
    if isinstance(response, dict):
        return response
    else:
        # Convert string response to dict for consistency
        return {
            "success": False,
            "error": response if isinstance(response, str) else "Unknown error"
        }

@mcp.tool()
def emulator_run(max_steps: int = 1000, stop_on_breakpoint: bool = True, stop_address: str = None) -> Dict[str, Any]:
    """
    Run the emulator until a condition is met.
    
    Args:
        max_steps: Maximum number of steps to execute (to prevent infinite loops)
        stop_on_breakpoint: Whether to stop at breakpoints
        stop_address: Optional specific address to stop at (e.g., "0x1400")
        
    Returns:
        Dictionary containing the result of the run operation, including:
        - stepsExecuted: Number of steps executed
        - currentPC: Final program counter value
        - stoppedReason: Why execution stopped (maxStepsReached, breakpoint, targetAddress)
        - executedInstructions: List of instructions that were executed
    """
    params = {
        "maxSteps": str(max_steps),
        "stopOnBreakpoint": str(stop_on_breakpoint).lower()
    }
    
    if stop_address:
        params["stopAddress"] = stop_address
    
    response = safe_post("emulator/run", params)
    
    if isinstance(response, dict):
        return response
    else:
        # Convert string response to dict for consistency
        return {
            "success": False,
            "error": response if isinstance(response, str) else "Unknown error"
        }

@mcp.tool()
def emulator_get_state() -> Dict[str, Any]:
    """
    Get the current state of the emulator.
    
    Returns:
        Dictionary containing the current emulator state, including:
        - registers: Dictionary of register values
        - programCounter: Current program counter value
        - memory: Dictionary of modified memory locations
        - status: Current status ("running" or "stopped")
    """
    response = safe_get("emulator/getState")
    
    if isinstance(response, dict):
        return response
    else:
        # Convert string response to dict for consistency
        return {
            "success": False,
            "error": response if isinstance(response, str) else "Unknown error"
        }

@mcp.tool()
def emulator_get_writes() -> Dict[str, Any]:
    """
    Get a list of memory locations that were written during emulation.
    
    Returns:
        Dictionary containing information about memory writes, including:
        - writes: List of write objects with address, length, hexValue, and asciiValue
        - count: Number of write objects
    """
    response = safe_get("emulator/getWrites")
    
    if isinstance(response, dict):
        return response
    else:
        # Convert string response to dict for consistency
        return {
            "success": False,
            "error": response if isinstance(response, str) else "Unknown error"
        }

@mcp.tool()
def emulator_reset() -> Dict[str, Any]:
    """
    Reset the emulator to its initial state.
    
    Returns:
        Dictionary containing the result of the reset operation, including:
        - programCounter: The reset program counter value
        - message: Status message
    """
    response = safe_get("emulator/reset")
    
    if isinstance(response, dict):
        return response
    else:
        # Convert string response to dict for consistency
        return {
            "success": False,
            "error": response if isinstance(response, str) else "Unknown error"
        }

@mcp.tool()
def emulator_set_breakpoint(address: str) -> Dict[str, Any]:
    """
    Set a breakpoint at the specified address.
    
    Args:
        address: The address to set the breakpoint at (e.g., "0x1400")
        
    Returns:
        Dictionary containing the result of the operation, including:
        - address: The address where the breakpoint was set
        - added: Whether the breakpoint was added (false if it already existed)
    """
    response = safe_post("emulator/setBreakpoint", address)
    
    if isinstance(response, dict):
        return response
    else:
        # Convert string response to dict for consistency
        return {
            "success": False,
            "error": response if isinstance(response, str) else "Unknown error"
        }

@mcp.tool()
def emulator_clear_breakpoint(address: str) -> Dict[str, Any]:
    """
    Clear a breakpoint at the specified address.
    
    Args:
        address: The address to clear the breakpoint from (e.g., "0x1400")
        
    Returns:
        Dictionary containing the result of the operation, including:
        - address: The address where the breakpoint was cleared
        - removed: Whether the breakpoint was removed (false if it didn't exist)
    """
    response = safe_post("emulator/clearBreakpoint", address)
    
    if isinstance(response, dict):
        return response
    else:
        # Convert string response to dict for consistency
        return {
            "success": False,
            "error": response if isinstance(response, str) else "Unknown error"
        }

@mcp.tool()
def emulator_get_breakpoints() -> Dict[str, Any]:
    """
    Get a list of all active breakpoints.
    
    Returns:
        Dictionary containing information about breakpoints, including:
        - breakpoints: List of breakpoint addresses
        - count: Number of breakpoints
    """
    response = safe_get("emulator/getBreakpoints")
    
    if isinstance(response, dict):
        return response
    else:
        # Convert string response to dict for consistency
        return {
            "success": False,
            "error": response if isinstance(response, str) else "Unknown error"
        }

@mcp.tool()
def emulator_set_register(register: str, value: str) -> Dict[str, Any]:
    """
    Set the value of a specific register in the emulator.
    
    Args:
        register: The name of the register to modify (e.g., "EAX")
        value: The value to set (decimal or hex with "0x" prefix)
        
    Returns:
        Dictionary containing the result of the operation, including:
        - register: The register that was modified
        - value: The new value in hex
        - decimal: The new value in decimal
    """
    response = safe_post("emulator/setRegister", {
        "register": register,
        "value": value
    })
    
    if isinstance(response, dict):
        return response
    else:
        # Convert string response to dict for consistency
        return {
            "success": False,
            "error": response if isinstance(response, str) else "Unknown error"
        }

@mcp.tool()
def emulator_get_register(register: str) -> Dict[str, Any]:
    """
    Get the value of a specific register from the emulator.
    
    Args:
        register: The name of the register to read (e.g., "EAX")
        
    Returns:
        Dictionary containing the register value, including:
        - register: The register name
        - value: The register value in hex
        - decimal: The register value in decimal
    """
    response = safe_get("emulator/getRegister", {"register": register})
    
    if isinstance(response, dict):
        return response
    else:
        # Convert string response to dict for consistency
        return {
            "success": False,
            "error": response if isinstance(response, str) else "Unknown error"
        }

@mcp.tool()
def emulator_get_registers() -> Dict[str, Any]:
    """
    Get a list of all available registers and their values.
    
    Returns:
        Dictionary containing register information, including:
        - registers: List of register objects with name, value, and special flags
        - count: Number of registers
    """
    response = safe_get("emulator/getRegisters")
    
    if isinstance(response, dict):
        return response
    else:
        # Convert string response to dict for consistency
        return {
            "success": False,
            "error": response if isinstance(response, str) else "Unknown error"
        }

@mcp.tool()
def emulator_read_memory(address: str, length: int = 16) -> Dict[str, Any]:
    """
    Read bytes from a specified memory address in the emulator.
    
    Args:
        address: The address to read from (e.g., "0x1400")
        length: The number of bytes to read (default: 16, max: 4096)
        
    Returns:
        Dictionary containing the memory data, including:
        - address: The starting address
        - length: Number of bytes read
        - hexValue: Hex representation of the bytes
        - asciiValue: ASCII representation of the bytes
    """
    response = safe_get("emulator/readMemory", {
        "address": address,
        "length": str(length)
    })
    
    if isinstance(response, dict):
        return response
    else:
        # Convert string response to dict for consistency
        return {
            "success": False,
            "error": response if isinstance(response, str) else "Unknown error"
        }

@mcp.tool()
def emulator_write_memory(address: str, bytes_hex: str) -> Dict[str, Any]:
    """
    Write bytes to a specified memory address in the emulator.
    
    Args:
        address: The address to write to (e.g., "0x1400")
        bytes_hex: The bytes to write as a hex string (e.g., "deadbeef")
        
    Returns:
        Dictionary containing the result of the operation, including:
        - address: The address that was written to
        - bytesWritten: Number of bytes written
    """
    response = safe_post("emulator/writeMemory", {
        "address": address,
        "bytes": bytes_hex
    })
    
    if isinstance(response, dict):
        return response
    else:
        # Convert string response to dict for consistency
        return {
            "success": False,
            "error": response if isinstance(response, str) else "Unknown error"
        }

@mcp.tool()
def emulator_set_memory_read_tracking(enable: bool = True) -> Dict[str, Any]:
    """
    Enable or disable memory read tracking in the emulator.
    
    Args:
        enable: Whether to enable or disable memory read tracking
        
    Returns:
        Dictionary containing the result of the operation, including:
        - tracking: Whether tracking is now enabled
        - message: Status message
    """
    response = safe_post("emulator/setMemoryReadTracking", {
        "enable": str(enable).lower()
    })
    
    if isinstance(response, dict):
        return response
    else:
        # Convert string response to dict for consistency
        return {
            "success": False,
            "error": response if isinstance(response, str) else "Unknown error"
        }

@mcp.tool()
def emulator_get_reads() -> Dict[str, Any]:
    """
    Get a list of memory locations that were read during emulation.
    
    Returns:
        Dictionary containing information about memory reads, including:
        - reads: List of read objects with address, length, hexValue, and asciiValue
        - count: Number of read objects
    """
    response = safe_get("emulator/getReads")
    
    if isinstance(response, dict):
        return response
    else:
        # Convert string response to dict for consistency
        return {
            "success": False,
            "error": response if isinstance(response, str) else "Unknown error"
        }

@mcp.tool()
def emulator_set_stack_change_tracking(enable: bool = True) -> Dict[str, Any]:
    """
    Enable or disable stack change tracking in the emulator.
    
    Args:
        enable: Whether to enable or disable stack change tracking
        
    Returns:
        Dictionary containing the result of the operation, including:
        - tracking: Whether tracking is now enabled
        - message: Status message
    """
    response = safe_post("emulator/setStackChangeTracking", {
        "enable": str(enable).lower()
    })
    
    if isinstance(response, dict):
        return response
    else:
        # Convert string response to dict for consistency
        return {
            "success": False,
            "error": response if isinstance(response, str) else "Unknown error"
        }

@mcp.tool()
def emulator_get_stack_trace() -> Dict[str, Any]:
    """
    Get the stack trace from the emulator.
    
    Returns:
        Dictionary containing stack trace information, including:
        - stackTrace: List of stack frame objects with instruction and stack values
        - count: Number of stack frames
    """
    response = safe_get("emulator/getStackTrace")
    
    if isinstance(response, dict):
        return response
    else:
        # Convert string response to dict for consistency
        return {
            "success": False,
            "error": response if isinstance(response, str) else "Unknown error"
        }

@mcp.tool()
def emulator_set_conditional_breakpoint(address: str, condition: str) -> Dict[str, Any]:
    """
    Set a conditional breakpoint at the specified address.
    
    Args:
        address: The address to set the breakpoint at (e.g., "0x1400")
        condition: The condition expression (e.g., "EAX=0x10" or "ECX>5")
        
    Returns:
        Dictionary containing the result of the operation, including:
        - address: The address where the breakpoint was set
        - condition: The breakpoint condition
        - message: Status message
    """
    response = safe_post("emulator/setConditionalBreakpoint", {
        "address": address,
        "condition": condition
    })
    
    if isinstance(response, dict):
        return response
    else:
        # Convert string response to dict for consistency
        return {
            "success": False,
            "error": response if isinstance(response, str) else "Unknown error"
        }

@mcp.tool()
def emulator_get_conditional_breakpoints() -> Dict[str, Any]:
    """
    Get a list of all conditional breakpoints.
    
    Returns:
        Dictionary containing information about conditional breakpoints, including:
        - breakpoints: List of breakpoint objects with address and condition
        - count: Number of conditional breakpoints
    """
    response = safe_get("emulator/getConditionalBreakpoints")
    
    if isinstance(response, dict):
        return response
    else:
        # Convert string response to dict for consistency
        return {
            "success": False,
            "error": response if isinstance(response, str) else "Unknown error"
        }

@mcp.tool()
def emulator_import_memory(from_address: str, length: str) -> Dict[str, Any]:
    """
    Import memory bytes from emulator to the Ghidra program.
    
    Args:
        from_address: Starting address to import (e.g., "0x1400")
        length: Length of bytes to import (as a string)
        
    Returns:
        Dictionary containing the result of the import operation, including:
        - bytesWritten: Number of bytes written to program memory
        - fromAddress: The starting address
        - toAddress: The ending address
    """
    response = safe_post("emulator/importMemory", {
        "fromAddress": from_address,
        "length": length
    })
    
    if isinstance(response, dict):
        return response
    else:
        # Convert string response to dict for consistency
        return {
            "success": False,
            "error": response if isinstance(response, str) else "Unknown error"
        }

def safe_get(endpoint: str, params: Optional[Dict[str, Any]] = None) -> Union[Dict[str, Any], List[Dict[str, Any]], List[str]]:
    """
    Perform a GET request and parse JSON response.
    
    Args:
        endpoint: API endpoint to call
        params: Query parameters dictionary
        
    Returns:
        Parsed JSON response or error message list
    """
    if params is None:
        params = {}
        
    url = f"{ghidra_server_url}/{endpoint}"
    
    try:
        logger.debug(f"GET request to {url} with params {params}")
        response = requests.get(url, params=params, timeout=DEFAULT_TIMEOUT)
        response.encoding = 'utf-8'
        
        if response.ok:
            try:
                # Try to parse as JSON first
                return response.json()
            except json.JSONDecodeError:
                # Fall back to text response if not JSON
                logger.debug(f"Response is not JSON, returning as text lines")
                return response.text.splitlines()
        else:
            error_msg = f"Error {response.status_code}: {response.text.strip()}"
            logger.error(error_msg)
            return [error_msg]
            
    except requests.exceptions.Timeout:
        error_msg = f"Request to {url} timed out after {DEFAULT_TIMEOUT}s"
        logger.error(error_msg)
        return [error_msg]
    except requests.exceptions.ConnectionError:
        error_msg = f"Connection error to {url}. Is Ghidra running?"
        logger.error(error_msg)
        return [error_msg]
    except Exception as e:
        error_msg = f"Request failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [error_msg]

def safe_post(endpoint: str, data: Union[Dict[str, Any], str]) -> Union[Dict[str, Any], str]:
    """
    Perform a POST request and parse JSON response.
    
    Args:
        endpoint: API endpoint to call
        data: Either a dict to be sent as form data or a string to be sent as raw body
        
    Returns:
        Parsed JSON response or error message
    """
    url = f"{ghidra_server_url}/{endpoint}"
    
    try:
        logger.debug(f"POST request to {url}")
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=DEFAULT_TIMEOUT)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=DEFAULT_TIMEOUT)
        
        response.encoding = 'utf-8'
        
        if response.ok:
            try:
                # Try to parse as JSON first
                return response.json()
            except json.JSONDecodeError:
                # Fall back to text response if not JSON
                return response.text.strip()
        else:
            error_msg = f"Error {response.status_code}: {response.text.strip()}"
            logger.error(error_msg)
            return error_msg
            
    except requests.exceptions.Timeout:
        error_msg = f"Request to {url} timed out after {DEFAULT_TIMEOUT}s"
        logger.error(error_msg)
        return error_msg
    except requests.exceptions.ConnectionError:
        error_msg = f"Connection error to {url}. Is Ghidra running?"
        logger.error(error_msg)
        return error_msg
    except Exception as e:
        error_msg = f"Request failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return error_msg

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
    """
    List all function names in the program with pagination.
    
    Args:
        offset: Starting position for pagination
        limit: Maximum number of items to return
        
    Returns:
        List of function objects with details like name, address, signature, etc.
    """
    response = safe_get("methods", {"offset": offset, "limit": limit})
    
    # Handle the response appropriately
    if isinstance(response, dict) and response.get("success") is True:
        return response.get("items", [])
    elif isinstance(response, dict) and response.get("error"):
        logger.error(f"Error listing methods: {response.get('error')}")
        return []
    else:
        # Fallback for unexpected response format
        logger.warning(f"Unexpected response format from methods endpoint")
        return response if isinstance(response, list) else []

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
    """
    List all namespace/class names in the program with pagination.
    
    Args:
        offset: Starting position for pagination
        limit: Maximum number of items to return
        
    Returns:
        List of class objects with details like name, id, parent namespace, etc.
    """
    response = safe_get("classes", {"offset": offset, "limit": limit})
    
    # Handle the response appropriately
    if isinstance(response, dict) and response.get("success") is True:
        return response.get("items", [])
    elif isinstance(response, dict) and response.get("error"):
        logger.error(f"Error listing classes: {response.get('error')}")
        return []
    else:
        logger.warning(f"Unexpected response format from classes endpoint")
        return response if isinstance(response, list) else []

@mcp.tool()
def decompile_function(name: str) -> Dict[str, Any]:
    """
    Decompile a specific function by name and return the decompiled C code.
    
    Args:
        name: Name of the function to decompile
        
    Returns:
        Dictionary containing the decompiled code and function name
    """
    response = safe_post("decompile", name)
    
    if isinstance(response, dict):
        return response
    else:
        # Convert string response to dict for consistency
        return {"function": name, "decompiled": response, "success": not response.startswith("Error")}

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> Dict[str, Any]:
    """
    Rename a function by its current name to a new user-defined name.
    
    Args:
        old_name: Current function name
        new_name: New function name
        
    Returns:
        Dictionary with success status and message
    """
    response = safe_post("renameFunction", {"oldName": old_name, "newName": new_name})
    
    if isinstance(response, dict):
        return response
    else:
        # Convert string response to dict for consistency
        return {
            "success": not response.startswith("Error") and not response.startswith("Request failed"),
            "message": response,
            "oldName": old_name,
            "newName": new_name
        }

@mcp.tool()
def rename_data(address: str, new_name: str) -> Dict[str, Any]:
    """
    Rename a data label at the specified address.
    
    Args:
        address: Address of the data to rename
        new_name: New label for the data
        
    Returns:
        Dictionary with success status and message
    """
    response = safe_post("renameData", {"address": address, "newName": new_name})
    
    if isinstance(response, dict):
        return response
    else:
        # Convert string response to dict for consistency
        return {
            "success": not response.startswith("Error") and not response.startswith("Request failed"),
            "message": response,
            "address": address,
            "newName": new_name
        }

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
    """
    List all memory segments in the program with pagination.
    
    Args:
        offset: Starting position for pagination
        limit: Maximum number of items to return
        
    Returns:
        List of segment objects with details like name, start, end, permissions, etc.
    """
    response = safe_get("segments", {"offset": offset, "limit": limit})
    
    if isinstance(response, dict) and response.get("success") is True:
        return response.get("items", [])
    elif isinstance(response, dict) and response.get("error"):
        logger.error(f"Error listing segments: {response.get('error')}")
        return []
    else:
        logger.warning(f"Unexpected response format from segments endpoint")
        return response if isinstance(response, list) else []

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
    """
    List imported symbols in the program with pagination.
    
    Args:
        offset: Starting position for pagination
        limit: Maximum number of items to return
        
    Returns:
        List of import objects with details like name, address, namespace, etc.
    """
    response = safe_get("imports", {"offset": offset, "limit": limit})
    
    if isinstance(response, dict) and response.get("success") is True:
        return response.get("items", [])
    elif isinstance(response, dict) and response.get("error"):
        logger.error(f"Error listing imports: {response.get('error')}")
        return []
    else:
        logger.warning(f"Unexpected response format from imports endpoint")
        return response if isinstance(response, list) else []

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
    """
    List exported functions/symbols with pagination.
    
    Args:
        offset: Starting position for pagination
        limit: Maximum number of items to return
        
    Returns:
        List of export objects with details like name, address, namespace, etc.
    """
    response = safe_get("exports", {"offset": offset, "limit": limit})
    
    if isinstance(response, dict) and response.get("success") is True:
        return response.get("items", [])
    elif isinstance(response, dict) and response.get("error"):
        logger.error(f"Error listing exports: {response.get('error')}")
        return []
    else:
        logger.warning(f"Unexpected response format from exports endpoint")
        return response if isinstance(response, list) else []

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
    """
    List all non-global namespaces in the program with pagination.
    
    Args:
        offset: Starting position for pagination
        limit: Maximum number of items to return
        
    Returns:
        List of namespace objects with details like name, id, parent namespace, etc.
    """
    response = safe_get("namespaces", {"offset": offset, "limit": limit})
    
    if isinstance(response, dict) and response.get("success") is True:
        return response.get("items", [])
    elif isinstance(response, dict) and response.get("error"):
        logger.error(f"Error listing namespaces: {response.get('error')}")
        return []
    else:
        logger.warning(f"Unexpected response format from namespaces endpoint")
        return response if isinstance(response, list) else []

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
    """
    List defined data labels and their values with pagination.
    
    Args:
        offset: Starting position for pagination
        limit: Maximum number of items to return
        
    Returns:
        List of data objects with details like address, label, value, dataType, etc.
    """
    response = safe_get("data", {"offset": offset, "limit": limit})
    
    if isinstance(response, dict) and response.get("success") is True:
        return response.get("items", [])
    elif isinstance(response, dict) and response.get("error"):
        logger.error(f"Error listing data items: {response.get('error')}")
        return []
    else:
        logger.warning(f"Unexpected response format from data endpoint")
        return response if isinstance(response, list) else []

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
    """
    Search for functions whose name contains the given substring.
    
    Args:
        query: Search term to find in function names
        offset: Starting position for pagination
        limit: Maximum number of items to return
        
    Returns:
        List of matching function objects
    """
    if not query:
        logger.error("Search query is required")
        return []
        
    response = safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})
    
    if isinstance(response, dict) and response.get("success") is True:
        return response.get("items", [])
    elif isinstance(response, dict) and response.get("error"):
        logger.error(f"Error searching functions: {response.get('error')}")
        return []
    else:
        logger.warning(f"Unexpected response format from searchFunctions endpoint")
        return response if isinstance(response, list) else []
        
@mcp.tool()
def get_function_stats(continuation_token: str = "", limit: int = 5000) -> Dict[str, Any]:
    """
    Get detailed function statistics with pagination support.
    
    This function processes functions in chunks to avoid timeouts.
    
    Args:
        continuation_token: Token from previous request to continue processing
        limit: Maximum number of functions to process in this request
        
    Returns:
        Dictionary containing function statistics, including:
        - totalCount: Total number of functions
        - externalCount: Number of external functions
        - internalCount: Number of internal functions
        - processedCount: Number of functions processed so far
        - isComplete: Whether all functions have been processed
        - continuationToken: Token to use for the next request if not complete
    """
    response = safe_get("programInfo/functionStats", {
        "continuationToken": continuation_token,
        "limit": limit
    })
    
    if isinstance(response, dict) and response.get("success") is True:
        return {
            "stats": response.get("functionStats", {}),
            "isComplete": response.get("isComplete", False),
            "continuationToken": response.get("continuationToken", "")
        }
    else:
        logger.error("Failed to get function statistics")
        return {
            "stats": {},
            "isComplete": True,
            "continuationToken": ""
        }

@mcp.tool()
def get_symbol_stats(continuation_token: str = "", limit: int = 5000, symbol_type: str = None) -> Dict[str, Any]:
    """
    Get detailed symbol statistics with pagination support.
    
    This function processes symbols in chunks to avoid timeouts.
    
    Args:
        continuation_token: Token from previous request to continue processing
        limit: Maximum number of symbols to process in this request
        symbol_type: Optional filter for a specific symbol type
        
    Returns:
        Dictionary containing symbol statistics, including:
        - totalCount: Total number of symbols
        - <type>Count: Count for each symbol type
        - items: List of sample symbols (limited to 100)
        - isComplete: Whether all symbols have been processed
        - continuationToken: Token to use for the next request if not complete
    """
    params = {
        "continuationToken": continuation_token,
        "limit": limit
    }
    
    if symbol_type:
        params["symbolType"] = symbol_type
        
    response = safe_get("programInfo/symbolStats", params)
    
    if isinstance(response, dict) and response.get("success") is True:
        return {
            "stats": response.get("symbolStats", {}),
            "items": response.get("items", []),
            "isComplete": response.get("isComplete", False),
            "continuationToken": response.get("continuationToken", "")
        }
    else:
        logger.error("Failed to get symbol statistics")
        return {
            "stats": {},
            "items": [],
            "isComplete": True,
            "continuationToken": ""
        }

@mcp.tool()
def get_data_type_stats(continuation_token: str = "", limit: int = 5000) -> Dict[str, Any]:
    """
    Get detailed data type statistics with pagination support.
    
    This function processes data types in chunks to avoid timeouts.
    
    Args:
        continuation_token: Token from previous request to continue processing
        limit: Maximum number of data types to process in this request
        
    Returns:
        Dictionary containing data type statistics, including:
        - totalCount: Total number of data types
        - builtInCount: Number of built-in data types
        - userDefinedCount: Number of user-defined data types
        - items: List of sample data types (limited to 100)
        - isComplete: Whether all data types have been processed
        - continuationToken: Token to use for the next request if not complete
    """
    response = safe_get("programInfo/dataTypeStats", {
        "continuationToken": continuation_token,
        "limit": limit
    })
    
    if isinstance(response, dict) and response.get("success") is True:
        return {
            "stats": response.get("dataTypeStats", {}),
            "items": response.get("items", []),
            "isComplete": response.get("isComplete", False),
            "continuationToken": response.get("continuationToken", "")
        }
    else:
        logger.error("Failed to get data type statistics")
        return {
            "stats": {},
            "items": [],
            "isComplete": True,
            "continuationToken": ""
        }

@mcp.tool()
def get_complete_function_stats() -> Dict[str, Any]:
    """
    Get complete function statistics, handling pagination automatically.
    
    This may make multiple requests to gather all data.
    
    Returns:
        Complete function statistics
    """
    all_stats = None
    continuation_token = ""
    
    while True:
        # Make request with continuation token if we have one
        response = get_function_stats(continuation_token, 5000)
        
        if not all_stats:
            all_stats = response.get("stats", {})
        else:
            # Update counts from this batch
            current_stats = response.get("stats", {})
            all_stats["externalCount"] = current_stats.get("externalCount", 0)
            all_stats["internalCount"] = current_stats.get("internalCount", 0)
            all_stats["processedCount"] = current_stats.get("processedCount", 0)
        
        # Check if we're done
        if response.get("isComplete", False):
            break
            
        # Update continuation token for next batch
        continuation_token = response.get("continuationToken", "")
        if not continuation_token:
            break
    
    return all_stats

@mcp.tool()
def get_complete_symbol_stats(symbol_type: str = None) -> Dict[str, Any]:
    """
    Get complete symbol statistics, handling pagination automatically.
    
    Args:
        symbol_type: Optional filter for a specific symbol type
        
    Returns:
        Complete symbol statistics
    """
    all_stats = None
    all_items = []
    continuation_token = ""
    
    while True:
        # Make request with continuation token if we have one
        response = get_symbol_stats(continuation_token, 5000, symbol_type)
        
        if not all_stats:
            all_stats = response.get("stats", {})
        else:
            # Update counts from this batch
            current_stats = response.get("stats", {})
            for key, value in current_stats.items():
                if key.endswith("Count"):
                    all_stats[key] = value
        
        # Add items (up to a reasonable limit)
        if len(all_items) < 500:
            items = response.get("items", [])
            all_items.extend(items[:min(len(items), 500 - len(all_items))])
        
        # Check if we're done
        if response.get("isComplete", False):
            break
            
        # Update continuation token for next batch
        continuation_token = response.get("continuationToken", "")
        if not continuation_token:
            break
    
    return {
        "stats": all_stats,
        "items": all_items
    }

@mcp.tool()
def get_program_info(detail_level: str = "basic") -> Dict[str, Any]:
    """
    Get detailed metadata about the currently loaded program.
    
    Args:
        detail_level: Level of detail ("basic" or "full")
                      - "basic": Fast, returns only essential program information
                      - "full": Comprehensive but potentially slower for large binaries
    
    Returns:
        A dictionary containing program information including:
        - Basic program details (name, path, creation date)
        - Language and compiler specifications
        - Memory statistics (size, block count)
        
        When detail_level is "full", also includes enhanced statistics by fetching
        from specialized endpoints.
    """
    # Convert detail_level to the parameter expected by the server
    detail_param = "full" if detail_level.lower() == "full" else "basic"
    
    # Use a shorter timeout for the basic programInfo endpoint (should be fast now)
    timeout = 60
    
    # Custom request for programInfo
    url = f"{ghidra_server_url}/programInfo"
    try:
        logger.debug(f"GET request to {url} with params {{'detail': {detail_param}}}")
        response = requests.get(url, params={"detail": detail_param}, timeout=timeout)
        response.encoding = 'utf-8'
        
        if response.ok:
            try:
                # Try to parse as JSON
                response = response.json()
            except json.JSONDecodeError:
                logger.error(f"Failed to parse programInfo response as JSON")
                return {}
        else:
            error_msg = f"Error {response.status_code}: {response.text.strip()}"
            logger.error(error_msg)
            return {}
            
    except requests.exceptions.Timeout:
        error_msg = f"Request to {url} timed out after {timeout}s"
        logger.error(error_msg)
        return {}
    except requests.exceptions.ConnectionError:
        error_msg = f"Connection error to {url}. Is Ghidra running?"
        logger.error(error_msg)
        return {}
    except Exception as e:
        error_msg = f"Request failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return {}
    
    if not isinstance(response, dict) or not response.get("success", False):
        logger.warning(f"Unexpected response format from programInfo endpoint")
        return {}
        
    basic_info = response.get("programInfo", {})
    
    # If basic info requested, return as is
    if detail_level.lower() != "full":
        return basic_info
        
    # For full detail, fetch additional specialized data if needed
    try:
        # Get function stats
        function_stats = get_function_stats(limit=1000)
        if function_stats.get("stats"):
            # Update the function stats in the result
            if "functions" in basic_info:
                basic_info["functions"].update(function_stats.get("stats", {}))
                # Add flag to indicate if complete
                basic_info["functions"]["isComplete"] = function_stats.get("isComplete", False)
                if not function_stats.get("isComplete", False):
                    basic_info["functions"]["continuationToken"] = function_stats.get("continuationToken", "")
        
        # We don't automatically fetch all data for large binaries to avoid timeouts
        # Just note the availability of continued fetching
        if "symbols" in basic_info and basic_info["symbols"].get("totalCount", 0) > 0:
            basic_info["symbols"]["note"] = "Use get_symbol_stats() to fetch detailed symbol statistics"
            
        if "dataTypes" in basic_info:
            basic_info["dataTypes"]["note"] = "Use get_data_type_stats() to fetch detailed data type statistics"
            
        return basic_info
            
    except Exception as e:
        logger.error(f"Error fetching additional program info: {str(e)}")
        # Return what we have so far
        return basic_info
        
@mcp.tool()
def get_references(address: str) -> Dict[str, Any]:
    """
    Get all references to and from the specified address.
    
    This function retrieves cross-references (xrefs) for a given address,
    showing both what references the address and what the address references.
    
    Args:
        address: The address to query for references (e.g., "0x1400")
        
    Returns:
        A dictionary containing:
        - address: The queried address
        - referencesToHere: List of references that point to this address
        - referencesFromHere: List of references that this address points to
        
    Each reference object contains information such as source/target addresses,
    reference type, and if applicable, function context.
    """
    if not address:
        logger.error("Address is required for reference lookup")
        return {
            "address": "",
            "referencesToHere": [],
            "referencesFromHere": []
        }
        
    response = safe_get("xrefs", {"address": address})
    
    if isinstance(response, dict) and response.get("success") is True:
        # Return just the data portion, removing the success flag for cleaner API
        result = {
            "address": response.get("address", ""),
            "referencesToHere": response.get("referencesToHere", []),
            "referencesFromHere": response.get("referencesFromHere", [])
        }
        return result
    elif isinstance(response, dict) and response.get("error"):
        logger.error(f"Error getting references: {response.get('error')}")
        return {
            "address": address,
            "referencesToHere": [],
            "referencesFromHere": [],
            "error": response.get("error")
        }
    else:
        logger.warning(f"Unexpected response format from xrefs endpoint")
        return {
            "address": address,
            "referencesToHere": [],
            "referencesFromHere": []
        }
        
@mcp.tool()
def disassemble_at_address(address: str, length: int = 10) -> Dict[str, Any]:
    """
    Get disassembly listing at a specific address for a given number of instructions.
    
    Args:
        address: The starting address to disassemble from (e.g., "0x1400")
        length: Number of instructions to disassemble (default: 10)
        
    Returns:
        A dictionary containing:
        - address: The starting address
        - instructions: List of instruction objects
        - count: Number of instructions returned
        - function: Name of the containing function (if any)
        
    Each instruction object contains details like address, bytes, mnemonic,
    full representation, operands, and comments if present.
    """
    if not address:
        logger.error("Address is required for disassembly")
        return {
            "address": "",
            "instructions": [],
            "count": 0
        }
        
    response = safe_get("disassemble", {"address": address, "length": length})
    
    if isinstance(response, dict) and response.get("success") is True:
        # Return just the data portion, removing the success flag for cleaner API
        result = {
            "address": response.get("address", ""),
            "instructions": response.get("instructions", []),
            "count": response.get("count", 0)
        }
        
        # Include function name if present
        if "function" in response:
            result["function"] = response["function"]
            
        return result
    elif isinstance(response, dict) and response.get("error"):
        logger.error(f"Error getting disassembly: {response.get('error')}")
        return {
            "address": address,
            "instructions": [],
            "count": 0,
            "error": response.get("error")
        }
    else:
        logger.warning(f"Unexpected response format from disassemble endpoint")
        return {
            "address": address,
            "instructions": [],
            "count": 0
        }
        
@mcp.tool()
def disassemble_function(name: str) -> Dict[str, Any]:
    """
    Get complete disassembly for a function by name.
    
    Args:
        name: Name of the function to disassemble
        
    Returns:
        A dictionary containing:
        - start: Starting address of the function
        - end: Ending address of the function
        - instructions: List of all instructions in the function
        - count: Number of instructions in the function
        - function: Function name
        - signature: Function signature
        
    Each instruction object contains detailed information including address,
    bytes, mnemonic, representation, operands, and comments if present.
    """
    if not name:
        logger.error("Function name is required")
        return {
            "instructions": [],
            "count": 0,
            "error": "Function name is required"
        }
        
    response = safe_post("disassembleFunction", name)
    
    if isinstance(response, dict) and response.get("success") is True:
        # Return just the data portion, removing the success flag for cleaner API
        result = {
            "start": response.get("start", ""),
            "end": response.get("end", ""),
            "instructions": response.get("instructions", []),
            "count": response.get("count", 0),
            "function": response.get("function", ""),
            "signature": response.get("signature", "")
        }
        return result
    elif isinstance(response, dict) and response.get("error"):
        logger.error(f"Error getting function disassembly: {response.get('error')}")
        return {
            "instructions": [],
            "count": 0,
            "error": response.get("error")
        }
    else:
        logger.warning(f"Unexpected response format from disassembleFunction endpoint")
        return {
            "function": name,
            "instructions": [],
            "count": 0
        }
        
@mcp.tool()
def set_comment(address: str, comment: str, comment_type: int = 3) -> Dict[str, Any]:
    """
    Set a comment at the specified address.
    
    Args:
        address: The address where to set the comment (e.g., "0x1400")
        comment: The comment text
        comment_type: Type of comment (default: 3 - EOL_COMMENT)
            - 1: PLATE_COMMENT (comment above a function)
            - 2: PRE_COMMENT (comment before an instruction)
            - 3: EOL_COMMENT (end-of-line comment)
            - 4: POST_COMMENT (comment after an instruction)
            - 5: REPEATABLE_COMMENT (comment that appears each time a function is referenced)
            
    Returns:
        A dictionary containing the result of the operation:
        - success: Whether the operation succeeded
        - address: The address where the comment was set
        - commentType: The numeric comment type
        - commentTypeName: The string name of the comment type
    """
    if not address:
        logger.error("Address is required for setting a comment")
        return {
            "success": False,
            "error": "Address is required"
        }
        
    response = safe_post("setComment", {
        "address": address,
        "comment": comment,
        "type": comment_type
    })
    
    if isinstance(response, dict):
        return response
    else:
        # Convert string response to dict for consistency
        return {
            "success": False,
            "address": address,
            "message": response if isinstance(response, str) else "Unknown error"
        }
        
    logger.warning(f"Unexpected response format from programInfo endpoint")
    return {}


if __name__ == "__main__":
    mcp.run()

