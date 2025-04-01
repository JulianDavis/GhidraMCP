# GhidraMCP Documentation

Welcome to the GhidraMCP documentation. This documentation provides comprehensive information about the Ghidra Model Context Protocol (MCP) plugin, which exposes Ghidra's functionality through an HTTP API.


## Documentation Structure

The documentation is organized into the following sections:

- **Architecture-Reference.md** - Comprehensive architecture documentation including component overview, package structure, and class responsibilities
- **API-Reference.md** - Complete API documentation for all HTTP endpoints
- **Development-Guide.md** - **MANDATORY instructions** for AI assistants on using JetBrains MCP tools for incremental Java development. Contains critical procedures that MUST be followed exactly.
- **Refactoring-Status.md** - Current progress of the refactoring effort

## Project Overview

GhidraMCP is a Ghidra plugin that exposes Ghidra's functionality through an HTTP API, enabling external tools to interact with Ghidra programmatically. The plugin provides endpoints for program analysis, disassembly, decompilation, data type management, and emulation.

## Current Status

The project is currently undergoing a major refactoring to improve its architecture and code organization. The refactoring aims to:

1. Implement a clear component hierarchy with well-defined responsibilities
2. Create properly separated service layers
3. Implement a clean HTTP API layer
4. Establish clear dependency relationships between components

The refactoring progress is being tracked in the `Refactoring-Status.md` file.

## Architecture

The architecture of the GhidraMCP plugin is documented in the `Architecture-Reference.md` file, which includes:

- Component hierarchy and responsibilities
- Package structure
- Class responsibilities
- Dependency relationships
- Implementation roadmap

## API Documentation

The API endpoints are documented in the `API-Reference.md` file, which provides comprehensive information about:

- Program Information endpoints
- Function endpoints
- Memory endpoints
- Data Type endpoints
- Disassembly endpoints
- Reference endpoints
- Emulation endpoints

## Emulation Features

The emulation architecture and endpoints are fully documented in both the `Architecture-Reference.md` and `API-Reference.md` files. The emulation component provides powerful dynamic analysis capabilities for binary code.

## Development Information

The `Development-Guide.md` file contains **MANDATORY instructions** for AI assistants working with the GhidraMCP codebase. This is not a set of optional guidelines - it provides critical instructions for:

- Required incremental development approach for Java code
- Exact patterns that MUST be followed when using JetBrains MCP tools
- Step-by-step methodologies for code modifications
- Verification procedures that are mandatory after each change

AI assistants MUST follow these instructions precisely when making any code changes. Failure to follow these instructions will result in corrupted code, lost work, and build failures.

## Navigation Guide

To find the information you need quickly:

- For understanding the overall architecture: See `Architecture-Reference.md`
- For API details and endpoint documentation: See `API-Reference.md`
- For development and contribution guidelines: See `Development-Guide.md`
- For current project status and progress: See `Refactoring-Status.md`

## Getting Started

To get started with the GhidraMCP plugin:

1. Refer to the `Architecture-Reference.md` file for an overview of the system
2. Check the `API-Reference.md` file for details on available endpoints
3. Monitor the `Refactoring-Status.md` file for the latest updates on the project
