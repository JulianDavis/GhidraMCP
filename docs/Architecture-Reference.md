# GhidraMCP Architecture Reference

This document provides a comprehensive reference for the GhidraMCP plugin architecture, covering the component hierarchy, package structure, class responsibilities, and dependency relationships.

## Architectural Overview

GhidraMCP is a Ghidra plugin that exposes Ghidra's functionality through an HTTP API, enabling external tools to interact with Ghidra programmatically. The plugin follows a modular architecture with clearly defined components, organized into logical layers.

### Core Architecture Principles

1. **Component Hierarchy**: Clear component structure with well-defined responsibilities
2. **Service-Oriented Design**: Functionality exposed through service interfaces
3. **Clean API Layer**: HTTP endpoints separated from business logic
4. **Dependency Management**: Clear dependency relationships between components

## Component Hierarchy

The GhidraMCP plugin is organized into the following major component groups:

### Plugin Infrastructure

- **GhidraMCPPlugin** - Main plugin entry point
- **ServiceRegistry** - Manages service registration and access
- **ConfigurationManager** - Manages plugin configuration
- **HttpServerManager** - Manages the HTTP server
- **EndpointRegistry** - Registers and manages HTTP endpoints

### API Layer

- **BaseHttpHandler** - Base class for all HTTP handlers
- **ProgramAnalysisHandler** - Handles program analysis endpoints
- **DisassemblyHandler** - Handles disassembly-related endpoints
- **DecompilerHandler** - Handles decompilation endpoints
- **MemoryOperationsHandler** - Handles memory-related endpoints
- **ReferenceHandler** - Handles cross-reference endpoints
- **DataTypeHandler** - Handles data type endpoints
- **EmulatorHandler** - Handles emulation endpoints

### Service Layer

- **ProgramInfoService** - Provides program metadata
- **MemoryCrossReferenceService** - Manages memory references
- **MemoryPatternSearchService** - Searches for patterns in memory
- **StringExtractionService** - Finds strings in memory
- **DataTypeService** - Manages data types
- **StructureAnalysisService** - Analyzes complex data structures

### Emulation Components

- **EmulatorService** - Core emulation engine
- **ArchitectureHelper** - Abstracts architecture differences
- **StdioEmulationHelper** - Emulates standard I/O
- **SyscallMappings** - Maps system calls
- **RegisterTrackingService** - Tracks register changes
- **StackTrackingService** - Tracks stack changes

## Package Structure

The code is organized into the following package structure:

```
com.juliandavis.ghidramcp
├── GhidraMCPPlugin.java              # Main plugin entry point
├── config/                           # Configuration related classes
├── api/                              # HTTP API layer
│   ├── server/                       # Server infrastructure
│   ├── handlers/                     # HTTP endpoint handlers
│   └── models/                       # API request/response models
├── core/                             # Core plugin functionality
│   ├── service/                      # Service registry and management
│   └── util/                         # Shared utility classes
├── analysis/                         # Program analysis components
│   ├── memory/                       # Memory analysis services
│   ├── function/                     # Function analysis services
│   ├── data/                         # Data type and structure services
│   └── search/                       # Search-related services
└── emulation/                        # Emulation components
    ├── core/                         # Core emulation engine
    ├── arch/                         # Architecture-specific functionality
    ├── io/                           # I/O emulation
    ├── syscall/                      # System call handling
    └── tracker/                      # Execution state tracking
```

### Package Descriptions

#### config

Contains classes related to plugin configuration, such as:
- `ConfigurationManager` - Manages loading and saving configuration
- `ConfigOption` - Represents a configuration option

#### api

Contains classes related to the HTTP API:

- **api.server**
  - `HttpServerManager` - Manages the HTTP server
  - `EndpointRegistry` - Registers and routes endpoints

- **api.handlers**
  - `BaseHttpHandler` - Base class for HTTP handlers
  - Specific handlers for different functionality areas

- **api.models**
  - Request and response model classes
  - Data transfer objects (DTOs)

#### core

Contains core plugin functionality:

- **core.service**
  - `ServiceRegistry` - Registry for plugin services
  - `Service` - Base interface for services

- **core.util**
  - Utility classes and functions used throughout the plugin

#### analysis

Contains program analysis components:

- **analysis.memory**
  - `MemoryCrossReferenceService` - Finds references to and from memory locations
  - `MemoryPatternSearchService` - Searches for patterns in memory

- **analysis.function**
  - `FunctionAnalysisService` - Analyzes functions and their properties

- **analysis.data**
  - `DataTypeService` - Manages data types

- **analysis.search**
  - `StringExtractionService` - Extracts strings from memory

#### emulation

Contains emulation components:

- **emulation.core**
  - `EmulatorService` - Core emulation service
  - `EmulatorSession` - Represents an emulation session

- **emulation.arch**
  - `ArchitectureHelper` - Handles architecture-specific operations

- **emulation.io**
  - `StdioEmulationHelper` - Handles standard I/O emulation

- **emulation.syscall**
  - `SyscallMappings` - Maps system call numbers to names and info

- **emulation.tracker**
  - Trackers for emulator state (registers, memory, stack)

## Class Responsibilities

### Main Plugin

#### GhidraMCPPlugin
- Initializes the plugin
- Registers services
- Sets up the HTTP server
- Manages plugin lifecycle

### Core Infrastructure

#### ServiceRegistry
- Manages service registration and access
- Provides service discovery
- Handles dependency injection
- Manages service lifecycle

#### ConfigurationManager
- Loads and saves configuration
- Provides access to configuration options
- Validates configuration values

### HTTP Server

#### HttpServerManager
- Starts and stops the server
- Registers endpoint handlers
- Handles server configuration

#### EndpointRegistry
- Registers and manages HTTP endpoints
- Associates paths with handlers
- Provides request routing
- Supports middleware

#### BaseHttpHandler
- Provides common request processing functionality
- Handles error situations
- Standardizes response formats

### API Handlers

#### ProgramAnalysisHandler
- Exposes program metadata
- Provides function listing
- Handles segment information

#### DisassemblyHandler
- Provides instruction-level disassembly
- Handles function-level disassembly
- Supports address range disassembly

#### DecompilerHandler
- Exposes function decompilation
- Handles address range decompilation
- Provides AST access

#### MemoryOperationsHandler
- Exposes memory reading/writing
- Handles memory search
- Provides memory mapping information

#### ReferenceHandler
- Exposes reference lookup
- Handles reference creation
- Provides reference analysis

#### DataTypeHandler
- Exposes data type management
- Handles structure creation and modification
- Provides data type application

#### EmulatorHandler
- Exposes emulation control
- Handles emulation state management
- Provides emulation result access

### Analysis Services

#### ProgramInfoService
- Analyzes program structure
- Gathers statistics
- Provides summary information

#### MemoryCrossReferenceService
- Finds references to/from addresses
- Discovers potential references
- Analyzes reference patterns

#### MemoryPatternSearchService
- Finds byte patterns
- Supports different search modes
- Provides context for matches

#### StringExtractionService
- Extracts ASCII/Unicode strings
- Provides string context
- Supports filtering

#### DataTypeService
- Creates and modifies data types
- Applies types to memory
- Handles complex structures

#### StructureAnalysisService
- Discovers potential structures
- Analyzes structure fields
- Identifies common patterns

### Emulation Services

#### EmulatorService
- Manages emulation sessions
- Controls execution
- Provides state access

#### ArchitectureHelper
- Handles register mapping
- Manages stack operations
- Provides endianness support

#### StdioEmulationHelper
- Intercepts I/O function calls
- Handles formatted I/O
- Manages I/O buffers

#### SyscallMappings
- Provides syscall information
- Maps numbers to names
- Supports different OS ABIs

#### RegisterTrackingService
- Records register values over time
- Provides register history
- Analyzes register usage

#### StackTrackingService
- Records stack operations
- Analyzes stack frames
- Provides stack trace

## Dependency Relationships

### Primary Dependencies

```
GhidraMCPPlugin
    ├── ServiceRegistry
    │   ├── Analysis Services
    │   │   ├── ProgramInfoService
    │   │   ├── MemoryCrossReferenceService
    │   │   ├── MemoryPatternSearchService
    │   │   ├── StringExtractionService
    │   │   ├── DataTypeService
    │   │   └── StructureAnalysisService
    │   └── Emulation Services
    │       ├── EmulatorService
    │       │   ├── ArchitectureHelper
    │       │   ├── StdioEmulationHelper
    │       │   └── SyscallMappings
    │       ├── RegisterTrackingService
    │       └── StackTrackingService
    └── HttpServerManager
        └── EndpointRegistry
            ├── ProgramAnalysisHandler
            ├── DisassemblyHandler
            ├── DecompilerHandler
            ├── MemoryOperationsHandler
            ├── ReferenceHandler
            ├── DataTypeHandler
            └── EmulatorHandler
```

### Key Dependencies

* `GhidraMCPPlugin` → `ServiceRegistry`, `HttpServerManager`
* `HttpServerManager` → `EndpointRegistry`
* `EndpointRegistry` → API Handlers
* API Handlers → Analysis and Emulation Services
* `EmulatorService` → `ArchitectureHelper`, `StdioEmulationHelper`, `SyscallMappings`

### Service Dependencies

* `MemoryCrossReferenceService` - No major dependencies
* `MemoryPatternSearchService` - No major dependencies
* `StringExtractionService` - No major dependencies
* `DataTypeService` - No major dependencies
* `EmulatorService` - Dependencies: `ArchitectureHelper`, `StdioEmulationHelper`, `SyscallMappings`

## Component Interaction Flow

1. The GhidraMCPPlugin initializes the ServiceRegistry and HttpServerManager
2. The HttpServerManager uses the EndpointRegistry to register HTTP endpoint handlers
3. When an HTTP request arrives, the appropriate handler is invoked
4. The handler delegates to the appropriate services for business logic
5. The services use Ghidra's API to access and modify program state
6. Results are returned through the service to the handler
7. The handler formats the response and returns it to the client

## Design Patterns Used

1. **Service Locator Pattern**: The ServiceRegistry provides a central point of access for services
2. **Façade Pattern**: The HTTP handlers provide a simplified interface to complex subsystems
3. **Dependency Injection**: Services are injected into handlers to promote loose coupling
4. **Strategy Pattern**: Different implementations can be provided for common interfaces
5. **Template Method Pattern**: BaseHttpHandler defines the skeleton of request handling algorithms

## Implementation Roadmap

The implementation follows a phased approach:

1. **Phase 1**: Refactor package structure and create base infrastructure classes
2. **Phase 2**: Migrate existing services to new structure
3. **Phase 3**: Refactor HTTP handlers to use new organization
4. **Phase 4**: Implement new services and handlers
5. **Phase 5**: Update the main plugin class to use the new infrastructure
6. **Phase 6**: Testing and documentation
