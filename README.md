[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub stars](https://img.shields.io/github/stars/JulianDavis/GhidraMCP)](https://github.com/JulianDavis/GhidraMCP/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/JulianDavis/GhidraMCP)](https://github.com/JulianDavis/GhidraMCP/network/members)

![ghidra_MCP_logo](https://github.com/user-attachments/assets/4986d702-be3f-4697-acce-aea55cd79ad3)


# GhidraMCP with Rich Result Objects
This is a fork of [LaurieWired's GhidraMCP](https://github.com/LaurieWired/GhidraMCP) with improved JSON responses for all endpoints and rich result objects. It is a Model Context Protocol server for allowing LLMs to autonomously reverse engineer applications. It exposes numerous tools from core Ghidra functionality to MCP clients.

https://github.com/user-attachments/assets/36080514-f227-44bd-af84-78e29ee1d7f9


# Features
MCP Server + Ghidra Plugin

- Decompile and analyze binaries in Ghidra
- Automatically rename methods and data
- List methods, classes, imports, and exports
- **All endpoints return JSON responses with consistent structure**
- **Pagination metadata included in all list responses**
- **Enhanced data fields in all responses**
- **Rich result objects with proper Python typing**
- **Consistent error handling across all endpoints**
- **Text responses automatically converted to structured JSON**

# Installation

## Prerequisites
- Install [Ghidra](https://ghidra-sre.org)
- Python3
- MCP [SDK](https://github.com/modelcontextprotocol/python-sdk)

## Ghidra
First, download the latest release from this repository. This contains the Ghidra plugin and Python MCP client. Then, you can directly import the plugin into Ghidra.

1. Run Ghidra
2. Select `File` -> `Install Extensions`
3. Click the `+` button
4. Select the `GhidraMCP-1-0.zip` (or your chosen version) from the downloaded release
5. Restart Ghidra
6. Make sure the GhidraMCPPlugin is enabled in `File` -> `Configure` -> `Developer`

Video Installation Guide:


https://github.com/user-attachments/assets/75f0c176-6da1-48dc-ad96-c182eb4648c3



## MCP Clients

Theoretically, any MCP client should work with ghidraMCP. Two examples are given below.

## Example 1: Claude Desktop
To set up Claude Desktop as a Ghidra MCP client, go to `Claude` -> `Settings` -> `Developer` -> `Edit Config` -> `claude_desktop_config.json` and add the following:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": [
        "/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py"
      ]
    }
  }
}
```

Alternatively, edit this file directly:
```
/Users/YOUR_USER/Library/Application Support/Claude/claude_desktop_config.json
```

## Example 2: 5ire
Another MCP client that supports multiple models on the backend is [5ire](https://github.com/nanbingxyz/5ire). To set up GhidraMCP, open 5ire and go to `Tools` -> `New` and set the following configurations:

1. Tool Key: ghidra
2. Name: GhidraMCP
3. Command: `python /ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py`

# JSON Response Format
All endpoints now return JSON responses with a consistent structure, which are then parsed into rich result objects:

## List Endpoints
```json
{
  "items": [
    {
      "name": "example_function",
      "address": "0x12345678",
      "signature": "void example_function(int param1)",
      "returnType": "void",
      "parameterCount": 1
    },
    ...
  ],
  "total": 100,
  "offset": 0,
  "limit": 10,
  "success": true
}
```

## Error Responses
```json
{
  "success": false,
  "error": "Error message here",
  "status_code": 404
}
```

## Rich Result Objects
The Python bridge now provides strongly-typed result objects for all endpoints:

```python
# Example of using rich result objects
result = emulator_get_state()

if isinstance(result, EmulatorState):
    # Access properties with type hints and auto-completion
    pc = result.programCounter
    registers = result.registers
    status = result.status
elif isinstance(result, ErrorResult):
    # Handle error
    error_message = result.error
```

## Consistent Text Response Handling
Non-JSON responses are automatically converted to structured data:

```json
{
  "success": true,
  "type": "text_response",
  "text": "Operation completed successfully",
  "lines": ["Operation", "completed", "successfully"]
}
```

# Building from Source
Build with Maven by running:

`mvn clean package assembly:single`

The generated zip file includes the built Ghidra plugin and its resources. These files are required for Ghidra to recognize the new extension.

- lib/GhidraMCP.jar
- extensions.properties
- Module.manifest

# Original Project
This is a fork of [LaurieWired's GhidraMCP](https://github.com/LaurieWired/GhidraMCP). All credit for the original implementation goes to the original author.