# GhidraMCP API Reference

This document provides comprehensive documentation for the HTTP API endpoints exposed by the GhidraMCP plugin.

## API Overview

The GhidraMCP API allows external tools to interact with Ghidra programmatically, providing access to program analysis, disassembly, decompilation, data type management, and emulation capabilities. All endpoints are exposed via HTTP, accepting and returning JSON data.

## Endpoint Categories

The API is organized into the following categories:

1. **Program Information** - Endpoints for retrieving program metadata
2. **Functions** - Endpoints for function analysis and manipulation
3. **Memory** - Endpoints for memory access and searching
4. **Data Types** - Endpoints for data type management
5. **Disassembly** - Endpoints for disassembly and decompilation
6. **References** - Endpoints for cross-reference analysis
7. **Emulation** - Endpoints for dynamic analysis through emulation

## Common Response Format

All API responses follow a standard format:

```json
{
  "status": "success" | "error",
  "data": { ... },  // Present on success
  "error": {        // Present on error
    "message": "Error message",
    "code": 123
  }
}
```

## Program Information Endpoints

These endpoints provide access to program metadata and structure information.

### GET /programInfo

Get detailed metadata about the currently loaded program.

**Parameters**: None

**Response**:

```json
{
  "status": "success",
  "data": {
    "name": "example.exe",
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "format": "Portable Executable (PE)",
    "architecture": "x86",
    "baseAddress": "0x400000",
    "creationDate": "2023-01-15T12:30:45Z",
    "compiler": "Microsoft Visual C++",
    "language": "x86:LE:32:default",
    "endian": "little",
    "executable": true,
    "size": 1048576
  }
}
```

### GET /programInfo/functionStats

Get function statistics with pagination support.

**Parameters**:

- `continuation_token` (optional): Token for requesting next page
- `limit` (optional): Maximum number of functions to process (default: 5000)

**Response**:

```json
{
  "status": "success",
  "data": {
    "totalCount": 1523,
    "externalCount": 123,
    "internalCount": 1400,
    "processedCount": 1000,
    "isComplete": false,
    "continuationToken": "eyJsYXN0SWQiOjEwMDB9",
    "items": [
      {
        "name": "main",
        "address": "0x401000",
        "size": 245
      }
      // Additional items...
    ]
  }
}
```

### GET /programInfo/symbolStats

Get symbol statistics with pagination support.

**Parameters**:

- `continuation_token` (optional): Token for requesting next page
- `limit` (optional): Maximum number of symbols to process (default: 5000)
- `symbol_type` (optional): Filter for a specific symbol type

**Response**:

```json
{
  "status": "success",
  "data": {
    "totalCount": 3542,
    "functionCount": 1523,
    "labelCount": 1843,
    "importCount": 176,
    "processedCount": 1000,
    "isComplete": false,
    "continuationToken": "eyJsYXN0SWQiOjEwMDB9",
    "items": [
      {
        "name": "main",
        "address": "0x401000",
        "type": "function"
      }
      // Additional items...
    ]
  }
}
```

### GET /programInfo/dataTypeStats

Get data type statistics with pagination support.

**Parameters**:

- `continuation_token` (optional): Token for requesting next page
- `limit` (optional): Maximum number of data types to process (default: 5000)

**Response**:

```json
{
  "status": "success",
  "data": {
    "totalCount": 875,
    "builtInCount": 543,
    "userDefinedCount": 332,
    "processedCount": 500,
    "isComplete": false,
    "continuationToken": "eyJsYXN0SWQiOjUwMH0=",
    "items": [
      {
        "name": "HANDLE",
        "category": "Windows",
        "size": 4,
        "type": "typedef"
      }
      // Additional items...
    ]
  }
}
```

### GET /segments

List memory segments with pagination.

**Parameters**:

- `offset` (optional): Starting position for pagination (default: 0)
- `limit` (optional): Maximum number of items to return (default: 100)

**Response**:

```json
{
  "status": "success",
  "data": {
    "segments": [
      {
        "name": ".text",
        "start": "0x401000",
        "end": "0x456000",
        "readable": true,
        "writable": false,
        "executable": true,
        "size": 348160
      },
      {
        "name": ".data",
        "start": "0x456000",
        "end": "0x458000",
        "readable": true,
        "writable": true,
        "executable": false,
        "size": 8192
      }
      // Additional segments...
    ],
    "count": 8,
    "offset": 0,
    "limit": 100,
    "total": 8
  }
}
```

### GET /imports

List imported symbols with pagination.

**Parameters**:

- `offset` (optional): Starting position for pagination (default: 0)
- `limit` (optional): Maximum number of items to return (default: 100)

**Response**:

```json
{
  "status": "success",
  "data": {
    "imports": [
      {
        "name": "GetProcAddress",
        "address": "0x410234",
        "library": "KERNEL32.dll",
        "ordinal": 0
      },
      {
        "name": "LoadLibraryA",
        "address": "0x410240",
        "library": "KERNEL32.dll",
        "ordinal": 0
      }
      // Additional imports...
    ],
    "count": 176,
    "offset": 0,
    "limit": 100,
    "total": 176
  }
}
```

### GET /exports

List exported functions/symbols with pagination.

**Parameters**:

- `offset` (optional): Starting position for pagination (default: 0)
- `limit` (optional): Maximum number of items to return (default: 100)

**Response**:

```json
{
  "status": "success",
  "data": {
    "exports": [
      {
        "name": "Initialize",
        "address": "0x401500",
        "ordinal": 1
      },
      {
        "name": "Cleanup",
        "address": "0x401620",
        "ordinal": 2
      }
      // Additional exports...
    ],
    "count": 24,
    "offset": 0,
    "limit": 100,
    "total": 24
  }
}
```

### GET /namespaces

List all non-global namespaces with pagination.

**Parameters**:

- `offset` (optional): Starting position for pagination (default: 0)
- `limit` (optional): Maximum number of items to return (default: 100)

**Response**:

```json
{
  "status": "success",
  "data": {
    "namespaces": [
      {
        "name": "std",
        "id": "namespace_1",
        "parent": "global"
      },
      {
        "name": "common",
        "id": "namespace_2",
        "parent": "global"
      }
      // Additional namespaces...
    ],
    "count": 15,
    "offset": 0,
    "limit": 100,
    "total": 15
  }
}
```

### GET /classes

List all namespace/class names with pagination.

**Parameters**:

- `offset` (optional): Starting position for pagination (default: 0)
- `limit` (optional): Maximum number of items to return (default: 100)

**Response**:

```json
{
  "status": "success",
  "data": {
    "classes": [
      {
        "name": "String",
        "id": "class_1",
        "parent": "std",
        "size": 32
      },
      {
        "name": "Vector",
        "id": "class_2",
        "parent": "std",
        "size": 16
      }
      // Additional classes...
    ],
    "count": 28,
    "offset": 0,
    "limit": 100,
    "total": 28
  }
}
```

## Function Endpoints

These endpoints provide access to function analysis and manipulation capabilities.

### GET /methods

List functions with pagination.

**Parameters**:

- `offset` (optional): Starting position for pagination (default: 0)
- `limit` (optional): Maximum number of items to return (default: 100)

**Response**:

```json
{
  "status": "success",
  "data": {
    "functions": [
      {
        "name": "main",
        "address": "0x401000",
        "signature": "int main(int argc, char **argv)",
        "entryPoint": "0x401000",
        "size": 245,
        "parameterCount": 2,
        "returnType": "int",
        "callingConvention": "__cdecl"
      },
      {
        "name": "initialize",
        "address": "0x401245",
        "signature": "bool initialize(void)",
        "entryPoint": "0x401245",
        "size": 89,
        "parameterCount": 0,
        "returnType": "bool",
        "callingConvention": "__cdecl"
      }
      // Additional functions...
    ],
    "count": 1523,
    "offset": 0,
    "limit": 100,
    "total": 1523
  }
}
```

### POST /renameFunction

Rename a function by its current name to a new user-defined name.

**Request**:

```json
{
  "old_name": "FUN_00401000",
  "new_name": "main"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "message": "Function renamed successfully",
    "old_name": "FUN_00401000",
    "new_name": "main",
    "address": "0x401000"
  }
}
```

### GET /searchFunctions

Search for functions whose name contains the given substring.

**Parameters**:

- `query`: Search term to find in function names
- `offset` (optional): Starting position for pagination (default: 0)
- `limit` (optional): Maximum number of items to return (default: 100)

**Response**:

```json
{
  "status": "success",
  "data": {
    "functions": [
      {
        "name": "initialize_system",
        "address": "0x401500",
        "signature": "void initialize_system(void)",
        "entryPoint": "0x401500",
        "size": 156
      },
      {
        "name": "initialize_network",
        "address": "0x401596",
        "signature": "bool initialize_network(void)",
        "entryPoint": "0x401596",
        "size": 223
      }
      // Additional matching functions...
    ],
    "count": 12,
    "offset": 0,
    "limit": 100,
    "total": 12
  }
}
```

### POST /defineFunction

Define a function at a specified address.

**Request**:

```json
{
  "address": "0x401000",
  "name": "main"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "message": "Function defined successfully",
    "name": "main",
    "address": "0x401000"
  }
}
```

### GET /identifyFunction

Identify if a function exists at a specified address.

**Parameters**:

- `address`: The address to check

**Response**:

```json
{
  "status": "success",
  "data": {
    "exists": true,
    "name": "main",
    "address": "0x401000",
    "signature": "int main(int argc, char **argv)",
    "entryPoint": "0x401000",
    "size": 245
  }
}
```

## Memory Endpoints

These endpoints provide access to memory operations and searching capabilities.

### GET /memory/searchPattern

Search for a pattern in memory.

**Parameters**:

- `pattern`: Byte pattern to search for (e.g., "90 90 ? ?")
- `start` (optional): Start address for the search
- `end` (optional): End address for the search
- `alignment` (optional): Alignment requirement (default: 1)
- `limit` (optional): Maximum number of matches to return (default: 100)

**Response**:

```json
{
  "status": "success",
  "data": {
    "matches": [
      {
        "address": "0x401234",
        "bytes": "90 90 55 8B",
        "context": "90 90 55 8B EC 83 EC 10"
      },
      {
        "address": "0x405678",
        "bytes": "90 90 55 8B",
        "context": "90 90 55 8B EC 56 57 8B"
      }
      // Additional matches...
    ],
    "count": 23,
    "pattern": "90 90 ? ?",
    "start": "0x401000",
    "end": "0x4A0000"
  }
}
```

### GET /memory/extractStrings

Extract strings from memory.

**Parameters**:

- `min_length` (optional): Minimum string length (default: 4)
- `encoding` (optional): String encoding ("ascii", "unicode", or "both", default: "both")
- `start` (optional): Start address for the search
- `end` (optional): End address for the search
- `limit` (optional): Maximum number of strings to return (default: 1000)

**Response**:

```json
{
  "status": "success",
  "data": {
    "strings": [
      {
        "address": "0x404000",
        "value": "Hello, World!",
        "encoding": "ascii",
        "length": 13
      },
      {
        "address": "0x404100",
        "value": "Error: File not found",
        "encoding": "unicode",
        "length": 20
      }
      // Additional strings...
    ],
    "count": 345,
    "encoding": "both",
    "min_length": 4,
    "start": "0x401000",
    "end": "0x4A0000"
  }
}
```

### GET /memory/findPotentialReferences

Find potential references to a memory address.

**Parameters**:

- `address`: The address to find references to
- `limit` (optional): Maximum number of references to return (default: 100)

**Response**:

```json
{
  "status": "success",
  "data": {
    "references": [
      {
        "from": "0x401234",
        "to": "0x404000",
        "type": "potential",
        "context": "8B 0D 00 40 40 00",
        "instruction": "MOV ECX,[0x404000]"
      },
      {
        "from": "0x401256",
        "to": "0x404000",
        "type": "potential",
        "context": "68 00 40 40 00",
        "instruction": "PUSH 0x404000"
      }
      // Additional references...
    ],
    "count": 5,
    "address": "0x404000"
  }
}
```

### GET /memory/getKnownReferences

Get known references to a memory address.

**Parameters**:

- `address`: The address to find references to
- `limit` (optional): Maximum number of references to return (default: 100)

**Response**:

```json
{
  "status": "success",
  "data": {
    "references": [
      {
        "from": "0x401234",
        "to": "0x404000",
        "type": "data",
        "context": "8B 0D 00 40 40 00",
        "instruction": "MOV ECX,[0x404000]"
      },
      {
        "from": "0x401256",
        "to": "0x404000",
        "type": "data",
        "context": "68 00 40 40 00",
        "instruction": "PUSH 0x404000"
      }
      // Additional references...
    ],
    "count": 5,
    "address": "0x404000"
  }
}
```

### GET /memory/getAllReferences

Get all references (known and potential) to a memory address.

**Parameters**:

- `address`: The address to find references to
- `limit` (optional): Maximum number of references to return (default: 100)

**Response**:

```json
{
  "status": "success",
  "data": {
    "references": [
      {
        "from": "0x401234",
        "to": "0x404000",
        "type": "data",
        "context": "8B 0D 00 40 40 00",
        "instruction": "MOV ECX,[0x404000]"
      },
      {
        "from": "0x402345",
        "to": "0x404000",
        "type": "potential",
        "context": "B8 00 40 40 00",
        "instruction": "MOV EAX,0x404000"
      }
      // Additional references...
    ],
    "count": 10,
    "address": "0x404000"
  }
}
```

### GET /data

List defined data items with pagination.

**Parameters**:

- `offset` (optional): Starting position for pagination (default: 0)
- `limit` (optional): Maximum number of items to return (default: 100)

**Response**:

```json
{
  "status": "success",
  "data": {
    "items": [
      {
        "address": "0x404000",
        "label": "g_systemState",
        "dataType": "SystemState",
        "size": 16,
        "value": "01 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00"
      },
      {
        "address": "0x404010",
        "label": "g_errorMessage",
        "dataType": "char[32]",
        "size": 32,
        "value": "45 72 72 6F 72 20 6F 63 63 75 72 72 65 64 2E 00"
      }
      // Additional data items...
    ],
    "count": 128,
    "offset": 0,
    "limit": 100,
    "total": 128
  }
}
```

## Data Type Endpoints

These endpoints provide access to data type management capabilities.

### GET /dataTypes/search

Search for data types.

**Parameters**:

- `query`: Search term to find in data type names
- `offset` (optional): Starting position for pagination (default: 0)
- `limit` (optional): Maximum number of items to return (default: 100)

**Response**:

```json
{
  "status": "success",
  "data": {
    "dataTypes": [
      {
        "name": "HANDLE",
        "category": "Windows",
        "size": 4,
        "type": "typedef"
      },
      {
        "name": "SOCKET_HANDLE",
        "category": "Network",
        "size": 4,
        "type": "typedef"
      }
      // Additional data types...
    ],
    "count": 8,
    "offset": 0,
    "limit": 100,
    "total": 8
  }
}
```

### GET /dataTypes/category

Get data types in a category.

**Parameters**:

- `category`: Category name
- `offset` (optional): Starting position for pagination (default: 0)
- `limit` (optional): Maximum number of items to return (default: 100)

**Response**:

```json
{
  "status": "success",
  "data": {
    "dataTypes": [
      {
        "name": "HANDLE",
        "category": "Windows",
        "size": 4,
        "type": "typedef"
      },
      {
        "name": "HWND",
        "category": "Windows",
        "size": 4,
        "type": "typedef"
      }
      // Additional data types...
    ],
    "count": 45,
    "category": "Windows",
    "offset": 0,
    "limit": 100,
    "total": 45
  }
}
```

### POST /dataTypes/createPrimitive

Create a primitive data type.

**Request**:

```json
{
  "name": "MyInt",
  "size": 4,
  "category": "Custom"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "message": "Primitive data type created successfully",
    "name": "MyInt",
    "category": "Custom",
    "size": 4
  }
}
```

### POST /dataTypes/createString

Create a string data type.

**Request**:

```json
{
  "name": "MyString",
  "length": 32,
  "category": "Custom",
  "fixed_length": true
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "message": "String data type created successfully",
    "name": "MyString",
    "category": "Custom",
    "length": 32,
    "fixed_length": true
  }
}
```

### POST /dataTypes/createArray

Create an array data type.

**Request**:

```json
{
  "name": "IntArray",
  "element_type": "int",
  "element_count": 10,
  "category": "Custom"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "message": "Array data type created successfully",
    "name": "IntArray",
    "category": "Custom",
    "element_type": "int",
    "element_count": 10,
    "size": 40
  }
}
```

### POST /dataTypes/createStructure

Create a structure data type.

**Request**:

```json
{
  "name": "Point",
  "category": "Custom",
  "fields": [
    {
      "name": "x",
      "type": "int",
      "offset": 0
    },
    {
      "name": "y",
      "type": "int",
      "offset": 4
    }
  ]
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "message": "Structure data type created successfully",
    "name": "Point",
    "category": "Custom",
    "size": 8,
    "field_count": 2
  }
}
```

### POST /dataTypes/addFieldToStructure

Add a field to a structure.

**Request**:

```json
{
  "structure_name": "Point",
  "field_name": "z",
  "field_type": "int",
  "offset": 8
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "message": "Field added to structure successfully",
    "structure_name": "Point",
    "field_name": "z",
    "offset": 8,
    "new_size": 12
  }
}
```

### POST /dataTypes/applyStructure

Apply a structure to memory.

**Request**:

```json
{
  "structure_name": "Point",
  "address": "0x404000"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "message": "Structure applied to memory successfully",
    "structure_name": "Point",
    "address": "0x404000",
    "size": 8
  }
}
```

### POST /dataTypes/createEnum

Create an enumeration data type.

**Request**:

```json
{
  "name": "Color",
  "category": "Custom",
  "size": 4,
  "values": [
    {
      "name": "RED",
      "value": 0
    },
    {
      "name": "GREEN",
      "value": 1
    },
    {
      "name": "BLUE",
      "value": 2
    }
  ]
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "message": "Enum data type created successfully",
    "name": "Color",
    "category": "Custom",
    "size": 4,
    "value_count": 3
  }
}
```

### POST /dataTypes/applyEnum

Apply an enum to memory.

**Request**:

```json
{
  "enum_name": "Color",
  "address": "0x404000"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "message": "Enum applied to memory successfully",
    "enum_name": "Color",
    "address": "0x404000",
    "size": 4
  }
}
```

### POST /dataTypes/delete

Delete a data type.

**Request**:

```json
{
  "name": "MyInt",
  "category": "Custom"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "message": "Data type deleted successfully",
    "name": "MyInt",
    "category": "Custom"
  }
}
```

## Disassembly Endpoints

These endpoints provide access to disassembly and decompilation capabilities.

### GET /disassemble

Get disassembly listing at a specific address.

**Parameters**:

- `address`: The starting address to disassemble from
- `length` (optional): Number of instructions to disassemble (default: 10)

**Response**:

```json
{
  "status": "success",
  "data": {
    "instructions": [
      {
        "address": "0x401000",
        "bytes": "55",
        "mnemonic": "PUSH",
        "operands": "EBP",
        "comment": "Function start"
      },
      {
        "address": "0x401001",
        "bytes": "8B EC",
        "mnemonic": "MOV",
        "operands": "EBP,ESP",
        "comment": null
      },
      {
        "address": "0x401003",
        "bytes": "83 EC 10",
        "mnemonic": "SUB",
        "operands": "ESP,0x10",
        "comment": "Allocate local variables"
      }
      // Additional instructions...
    ],
    "count": 10,
    "start_address": "0x401000"
  }
}
```

### GET /disassembleFunction

Get complete disassembly for a function.

**Parameters**:

- `name`: Name of the function to disassemble

**Response**:

```json
{
  "status": "success",
  "data": {
    "function": {
      "name": "main",
      "address": "0x401000",
      "size": 245
    },
    "instructions": [
      {
        "address": "0x401000",
        "bytes": "55",
        "mnemonic": "PUSH",
        "operands": "EBP",
        "comment": "Function start"
      },
      {
        "address": "0x401001",
        "bytes": "8B EC",
        "mnemonic": "MOV",
        "operands": "EBP,ESP",
        "comment": null
      }
      // Additional instructions...
    ],
    "count": 35,
    "start_address": "0x401000",
    "end_address": "0x4010F5"
  }
}
```

### GET /decompile

Decompile a function by name.

**Parameters**:

- `name`: Name of the function to decompile

**Response**:

```json
{
  "status": "success",
  "data": {
    "function": {
      "name": "main",
      "address": "0x401000",
      "signature": "int main(int argc, char **argv)"
    },
    "decompiled_code": "int main(int argc, char **argv) {\n  int result;\n  if (argc > 1) {\n    result = process_file(argv[1]);\n  } else {\n    printf(\"Usage: %s <filename>\\n\", argv[0]);\n    result = 1;\n  }\n  return result;\n}"
  }
}
```

### POST /decompileRange

Decompile code within an address range.

**Request**:

```json
{
  "start": "0x401000",
  "end": "0x401100"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "range": {
      "start": "0x401000",
      "end": "0x401100"
    },
    "decompiled_code": "int main(int argc, char **argv) {\n  // Decompiled code for the address range\n}",
    "functions": [
      {
        "name": "main",
        "address": "0x401000",
        "size": 245
      }
    ]
  }
}
```

### POST /setComment

Set a comment at a specified address.

**Request**:

```json
{
  "address": "0x401000",
  "comment": "Entry point of the program",
  "comment_type": 3
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "message": "Comment set successfully",
    "address": "0x401000",
    "comment_type": 3,
    "comment_type_name": "EOL_COMMENT"
  }
}
```

### POST /renameData

Rename a data label at the specified address.

**Request**:

```json
{
  "address": "0x404000",
  "new_name": "g_configData"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "message": "Data label renamed successfully",
    "address": "0x404000",
    "old_name": "DAT_00404000",
    "new_name": "g_configData"
  }
}
```

## Reference Endpoints

These endpoints provide access to cross-reference analysis.

### GET /xrefs

Get all references to and from the specified address.

**Parameters**:

- `address`: The address to query for references

**Response**:

```json
{
  "status": "success",
  "data": {
    "address": "0x404000",
    "referencesTo": [
      {
        "from": "0x401234",
        "type": "DATA",
        "context": "MOV ECX,[0x404000]"
      },
      {
        "from": "0x401256",
        "type": "DATA",
        "context": "PUSH 0x404000"
      }
      // Additional references to the address...
    ],
    "referencesFrom": [
      {
        "to": "0x405678",
        "type": "DATA_POINTER",
        "context": "Pointer to data at 0x405678"
      }
      // Additional references from the address...
    ],
    "count": {
      "to": 5,
      "from": 1
    }
  }
}
```

## Emulation Endpoints

These endpoints provide access to dynamic analysis through emulation.

### POST /emulator/initialize

Initialize an emulator session.

**Request**:

```json
{
  "address": "0x401000",
  "write_tracking": true
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "sessionId": "550e8400-e29b-41d4-a716-446655440000",
    "programCounter": "0x401000",
    "architecture": "x86",
    "initialized": true,
    "message": "Emulator session initialized"
  }
}
```

### POST /emulator/step

Step the emulator forward by one instruction.

**Request**:

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "oldProgramCounter": "0x401000",
    "newProgramCounter": "0x401001",
    "instruction": "PUSH EBP",
    "bytes": "55",
    "writesMemory": false,
    "readsMemory": false
  }
}
```

### POST /emulator/run

Run the emulator until a condition is met.

**Request**:

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000",
  "max_steps": 1000,
  "stop_on_breakpoint": true,
  "stop_address": "0x401050"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "startAddress": "0x401001",
    "endAddress": "0x401050",
    "steps": 42,
    "reason": "STOP_ADDRESS",
    "instruction": "CALL 0x401500",
    "bytes": "E8 AB 04 00 00"
  }
}
```

### GET /emulator/getState

Get the current state of the emulator.

**Request**:

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "programCounter": "0x401050",
    "registers": {
      "EAX": "0x00000001",
      "EBX": "0x00000000",
      "ECX": "0x0040A000",
      "EDX": "0x00000010",
      "ESI": "0x00000000",
      "EDI": "0x00000000",
      "EBP": "0x0062FE08",
      "ESP": "0x0062FE04"
    },
    "flags": {
      "ZERO": false,
      "CARRY": false,
      "OVERFLOW": false,
      "SIGN": false
    },
    "lastInstruction": "CALL 0x401500",
    "sessionId": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

### GET /emulator/getWrites

Get a list of memory locations that were written during emulation.

**Request**:

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "writes": [
      {
        "address": "0x0062FE04",
        "length": 4,
        "hexValue": "08 FE 62 00",
        "asciiValue": "..b.",
        "instruction": "0x401000: PUSH EBP"
      },
      {
        "address": "0x0062FE00",
        "length": 4,
        "hexValue": "54 10 40 00",
        "asciiValue": "T.@.",
        "instruction": "0x40104F: CALL 0x401500"
      }
      // Additional memory writes...
    ],
    "count": 12
  }
}
```

### GET /emulator/getReads

Get a list of memory locations that were read during emulation.

**Request**:

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "reads": [
      {
        "address": "0x00404000",
        "length": 4,
        "hexValue": "01 00 00 00",
        "asciiValue": "....",
        "instruction": "0x401025: MOV EAX,[0x404000]"
      },
      {
        "address": "0x00404004",
        "length": 4,
        "hexValue": "02 00 00 00",
        "asciiValue": "....",
        "instruction": "0x40102B: MOV ECX,[0x404004]"
      }
      // Additional memory reads...
    ],
    "count": 8
  }
}
```

### POST /emulator/setBreakpoint

Set a breakpoint at the specified address.

**Request**:

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000",
  "address": "0x401050"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "address": "0x401050",
    "added": true
  }
}
```

### POST /emulator/clearBreakpoint

Clear a breakpoint at the specified address.

**Request**:

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000",
  "address": "0x401050"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "address": "0x401050",
    "removed": true
  }
}
```

### GET /emulator/getBreakpoints

Get a list of all active breakpoints.

**Request**:

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "breakpoints": [
      "0x401050",
      "0x401100",
      "0x401200"
    ],
    "count": 3
  }
}
```

### POST /emulator/setConditionalBreakpoint

Set a conditional breakpoint at the specified address.

**Request**:

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000",
  "address": "0x401050",
  "condition": "EAX=0x10"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "address": "0x401050",
    "condition": "EAX=0x10",
    "message": "Conditional breakpoint set"
  }
}
```

### GET /emulator/getConditionalBreakpoints

Get a list of all conditional breakpoints.

**Request**:

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "breakpoints": [
      {
        "address": "0x401050",
        "condition": "EAX=0x10"
      },
      {
        "address": "0x401100",
        "condition": "ECX>5"
      }
    ],
    "count": 2
  }
}
```

### POST /emulator/setRegister

Set the value of a specific register in the emulator.

**Request**:

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000",
  "register": "EAX",
  "value": "0x10"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "register": "EAX",
    "value": "0x00000010",
    "decimal": 16
  }
}
```

### GET /emulator/getRegister

Get the value of a specific register from the emulator.

**Request**:

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000",
  "register": "EAX"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "register": "EAX",
    "value": "0x00000010",
    "decimal": 16
  }
}
```

### GET /emulator/getRegisters

Get a list of all available registers and their values.

**Request**:

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "registers": [
      {
        "name": "EAX",
        "value": "0x00000010",
        "isStackPointer": false,
        "isProgramCounter": false
      },
      {
        "name": "EBX",
        "value": "0x00000000",
        "isStackPointer": false,
        "isProgramCounter": false
      },
      {
        "name": "ESP",
        "value": "0x0062FE00",
        "isStackPointer": true,
        "isProgramCounter": false
      },
      {
        "name": "EIP",
        "value": "0x00401050",
        "isStackPointer": false,
        "isProgramCounter": true
      }
      // Additional registers...
    ],
    "count": 16
  }
}
```

### POST /emulator/writeMemory

Write bytes to a specified memory address in the emulator.

**Request**:

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000",
  "address": "0x404000",
  "bytes_hex": "01 02 03 04"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "address": "0x404000",
    "bytesWritten": 4
  }
}
```

### GET /emulator/readMemory

Read bytes from a specified memory address in the emulator.

**Request**:

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000",
  "address": "0x404000",
  "length": 16
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "address": "0x404000",
    "length": 16,
    "hexValue": "01 02 03 04 00 00 00 00 00 00 00 00 00 00 00 00",
    "asciiValue": "..............."
  }
}
```

### POST /emulator/setMemoryReadTracking

Enable or disable memory read tracking in the emulator.

**Request**:

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000",
  "enable": true
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "tracking": true,
    "message": "Memory read tracking enabled"
  }
}
```

### POST /emulator/setStackChangeTracking

Enable or disable stack change tracking in the emulator.

**Request**:

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000",
  "enable": true
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "tracking": true,
    "message": "Stack change tracking enabled"
  }
}
```

### GET /emulator/getStackTrace

Get the stack trace from the emulator.

**Request**:

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "stackTrace": [
      {
        "frameNumber": 0,
        "returnAddress": "0x401054",
        "function": "main+0x54",
        "stackPointer": "0x0062FE00",
        "parameters": [
          {
            "name": "arg1",
            "value": "0x00000001"
          },
          {
            "name": "arg2",
            "value": "0x0040A000"
          }
        ]
      },
      {
        "frameNumber": 1,
        "returnAddress": "0x401234",
        "function": "start+0x34",
        "stackPointer": "0x0062FE10",
        "parameters": []
      }
      // Additional stack frames...
    ],
    "count": 2
  }
}
```

### GET /emulator/getStdout

Get stdout content from the emulated program.

**Request**:

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "stdout": "Hello, World!\nProcessing data...\nDone.\n",
    "length": 35
  }
}
```

### GET /emulator/getStderr

Get stderr content from the emulated program.

**Request**:

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "stderr": "Warning: File not found\n",
    "length": 22
  }
}
```

### POST /emulator/provideStdin

Provide stdin data for the emulated program.

**Request**:

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000",
  "data": "test input\n"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "bytesAdded": 11,
    "message": "Input added to stdin buffer"
  }
}
```

### POST /emulator/importMemory

Import memory bytes from emulator to the Ghidra program.

**Request**:

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000",
  "from_address": "0x404000",
  "length": "16"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "bytesWritten": 16,
    "fromAddress": "0x404000",
    "toAddress": "0x404010"
  }
}
```

### POST /emulator/reset

Reset the emulator to its initial state.

**Request**:

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "programCounter": "0x401000",
    "message": "Emulator reset to initial state"
  }
}
```

### POST /emulator/dispose

Dispose of the emulator session.

**Request**:

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "message": "Emulator session disposed",
    "sessionId": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

### GET /emulator/getArchitectureInfo

Get architecture-specific information.

**Request**:

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "architecture": "x86",
    "endianness": "little",
    "pointerSize": 4,
    "stackGrowthDirection": -1,
    "programCounterRegister": "EIP",
    "stackPointerRegister": "ESP",
    "syscallNumberRegister": "EAX"
  }
}
```

### GET /emulator/getSyscallInfo

Get syscall information for a specific syscall number.

**Request**:

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000",
  "syscallNumber": 4
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "number": 4,
    "name": "write",
    "os": "linux",
    "architecture": "x86",
    "parameters": [
      {
        "position": 0,
        "name": "fd",
        "type": "int"
      },
      {
        "position": 1,
        "name": "buf",
        "type": "void*"
      },
      {
        "position": 2,
        "name": "count",
        "type": "size_t"
      }
    ],
    "returnType": "ssize_t",
    "description": "write to a file descriptor"
  }
}
```

### GET /emulator/getAllSyscalls

Get all syscalls for an OS/processor.

**Request**:

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000",
  "os": "linux",
  "architecture": "x86"
}
```

**Response**:

```json
{
  "status": "success",
  "data": {
    "os": "linux",
    "architecture": "x86",
    "syscalls": [
      {
        "number": 1,
        "name": "exit",
        "parameters": 1,
        "type": "void"
      },
      {
        "number": 2,
        "name": "fork",
        "parameters": 0,
        "type": "pid_t"
      },
      {
        "number": 3,
        "name": "read",
        "parameters": 3,
        "type": "ssize_t"
      },
      {
        "number": 4,
        "name": "write",
        "parameters": 3,
        "type": "ssize_t"
      }
      // Additional syscalls...
    ],
    "count": 350
  }
}
```
