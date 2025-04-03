# Emulator Service Migration Guide

This document provides instructions for safely transitioning from the legacy `com.juliandavis.EmulatorHttpHandler` to the new refactored implementation in `com.juliandavis.ghidramcp.api.handlers.EmulatorHttpHandler`.

## Migration Status

The emulator service has been fully refactored to match the reference architecture:

- ✅ `EmulatorService` moved to `com.juliandavis.ghidramcp.emulation.core`
- ✅ `EmulatorSession` moved to `com.juliandavis.ghidramcp.emulation.core`
- ✅ `EmulatorHttpHandler` moved to `com.juliandavis.ghidramcp.api.handlers`
- ✅ `ArchitectureHelper` moved to `com.juliandavis.ghidramcp.emulation.arch`
- ✅ `StdioEmulationHelper` moved to `com.juliandavis.ghidramcp.emulation.io`
- ✅ `SyscallMappings` moved to `com.juliandavis.ghidramcp.emulation.syscall`

## Safe Removal Process

To safely remove the old implementation:

1. Verify that the migration is complete by checking the logs for the message "Emulator endpoints migration verified successfully." If this message appears, the new implementation is working correctly.

2. The migration helper `EmulatorMigrationHelper` will attempt to:
   - Migrate any active emulator sessions from the old implementation to the new one
   - Disable the old EmulatorHttpHandler to prevent conflicts

3. After verifying that the new implementation is working correctly, you can safely remove the following files from the old package:
   - `src/main/java/com/juliandavis/EmulatorHttpHandler.java`
   - `src/main/java/com/juliandavis/EmulatorService.java`
   - `src/main/java/com/juliandavis/ArchitectureHelper.java`
   - `src/main/java/com/juliandavis/StdioEmulationHelper.java`

4. Then, update the `GhidraMCPPlugin` class to remove any references to the old implementation. Specifically, remove the following code from `startServer()` method:

```java
// Initialize and register emulator endpoints
EmulatorHttpHandler emulatorHandler = new EmulatorHttpHandler(this);
emulatorHandler.registerEndpoints();
```

## Verification

After removing the old implementation:

1. Start the plugin and check the logs. There should be no warnings about duplicate EmulatorHttpHandler implementations.

2. Test the emulator functionality to ensure that all endpoints are working correctly:
   - Initialize the emulator
   - Step execution
   - Get emulator state
   - Set and clear breakpoints
   - Read and write memory
   - Get and set register values

3. If you encounter any issues, restore the old implementation and file a bug report.

## Note to Users

Any existing emulator sessions will be lost during the migration. Users will need to re-initialize the emulator after the migration is complete.

## Technical Details

The emulation components have been refactored to better follow the reference architecture:

- `EmulatorService` is now a proper service that implements the `Service` interface
- `EmulatorHttpHandler` now extends `BaseHttpHandler` for consistent error handling
- The emulator components are now properly initialized through the `ServiceRegistry`
- Session management is more robust with UUID-based tracking

The new implementation provides the same functionality as the old one, but with improved architecture and code organization.