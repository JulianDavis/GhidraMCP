import pytest
import json
from unittest.mock import patch, MagicMock

# Import the bridge module - assuming it's in the same directory
from bridge_mcp_ghidra import (
    safe_get, safe_post, 
    list_methods, list_classes, 
    get_program_info
)

# Test the safe_get function with a successful JSON response
@patch('bridge_mcp_ghidra.requests.get')
def test_safe_get_json_success(mock_get):
    # Setup mock response
    mock_response = MagicMock()
    mock_response.ok = True
    mock_response.json.return_value = {"success": True, "items": [{"name": "test"}]}
    mock_get.return_value = mock_response
    
    # Call the function
    result = safe_get("test_endpoint")
    
    # Verify results
    assert isinstance(result, dict)
    assert result["success"] is True
    assert len(result["items"]) == 1
    assert result["items"][0]["name"] == "test"

# Test the safe_get function with a non-JSON response
@patch('bridge_mcp_ghidra.requests.get')
def test_safe_get_text_success(mock_get):
    # Setup mock response
    mock_response = MagicMock()
    mock_response.ok = True
    mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
    mock_response.text = "line1\nline2"
    mock_get.return_value = mock_response
    
    # Call the function
    result = safe_get("test_endpoint")
    
    # Verify results
    assert isinstance(result, list)
    assert len(result) == 2
    assert result[0] == "line1"
    assert result[1] == "line2"

# Test the safe_get function with an error response
@patch('bridge_mcp_ghidra.requests.get')
def test_safe_get_error(mock_get):
    # Setup mock response
    mock_response = MagicMock()
    mock_response.ok = False
    mock_response.status_code = 404
    mock_response.text = "Not Found"
    mock_get.return_value = mock_response
    
    # Call the function
    result = safe_get("test_endpoint")
    
    # Verify results
    assert isinstance(result, list)
    assert len(result) == 1
    assert "Error 404" in result[0]

# Test the list_methods function with a successful response
@patch('bridge_mcp_ghidra.safe_get')
def test_list_methods_success(mock_safe_get):
    # Setup mock response
    mock_safe_get.return_value = {
        "success": True,
        "items": [
            {"name": "function1", "address": "0x1000"},
            {"name": "function2", "address": "0x2000"}
        ],
        "total": 2
    }
    
    # Call the function
    result = list_methods()
    
    # Verify results
    assert isinstance(result, list)
    assert len(result) == 2
    assert result[0]["name"] == "function1"
    assert result[1]["address"] == "0x2000"

# Test the get_program_info function
@patch('bridge_mcp_ghidra.safe_get')
def test_get_program_info(mock_safe_get):
    # Setup mock response
    mock_safe_get.return_value = {
        "success": True,
        "programInfo": {
            "name": "TestProgram",
            "location": "/path/to/program",
            "processor": {
                "name": "x86",
                "endian": "little"
            }
        }
    }
    
    # Call the function
    result = get_program_info()
    
    # Verify results
    assert isinstance(result, dict)
    assert result["name"] == "TestProgram"
    assert result["location"] == "/path/to/program"
    assert result["processor"]["name"] == "x86"
    assert result["processor"]["endian"] == "little"

# Test error handling in get_program_info
@patch('bridge_mcp_ghidra.safe_get')
def test_get_program_info_error(mock_safe_get):
    # Setup mock response for error
    mock_safe_get.return_value = {
        "success": False,
        "error": "No program loaded"
    }
    
    # Call the function
    result = get_program_info()
    
    # Verify results
    assert isinstance(result, dict)
    assert len(result) == 0  # Should return an empty dict on error
