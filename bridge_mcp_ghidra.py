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
DEFAULT_TIMEOUT = 10  # Increased timeout for large binaries

mcp = FastMCP("ghidra-mcp")

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
def get_program_info() -> Dict[str, Any]:
    """
    Get detailed metadata about the currently loaded program.
    
    Returns:
        A dictionary containing comprehensive program information including:
        - Basic program details (name, path, creation date)
        - Language and compiler specifications
        - Memory statistics (size, block count)
        - Function statistics (total, external, internal counts)
        - Symbol statistics (total, external, label counts)
        - Data type statistics
        - Processor architecture information
    """
    response = safe_get("programInfo")
    
    if isinstance(response, dict) and response.get("success") is True:
        return response.get("programInfo", {})
    elif isinstance(response, dict) and response.get("error"):
        logger.error(f"Error getting program info: {response.get('error')}")
        return {}
    else:
        logger.warning(f"Unexpected response format from programInfo endpoint")
        return {}
        
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

