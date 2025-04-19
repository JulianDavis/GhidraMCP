# Ghidra MCP Plugin Enhancement Plan

This document outlines planned improvements for the Ghidra MCP bridge and backend plugin, based on analysis and identified needs during reverse engineering tasks.

## Phase 1: Core Improvements & Addressing Immediate Needs

1.  **New Tool: `set_variable_data_type`**
    *   **Goal:** Allow re-typing local variables in the decompiler view. Addresses the `logContext` issue directly.
    *   **Ghidra Cmd:** `ghidra.app.cmd.function.SetVariableDataTypeCmd`
    *   **Details:** Create tool `set_variable_data_type(function_name: str, variable_name: str, data_type_name: str)` calling a new backend endpoint (`/decompiler/setVariableDataType`). Backend service method needs access to `PluginTool` to execute the command. Requires robust variable and data type lookup.
    *   **Status:** Completed. Python tool added, Java service method implemented to access SetVariableDataTypeCmd via PluginTool, and HTTP handler added with proper parameter validation.

2.  **Modify Tool: `create_structure_data_type`**
    *   **Goal:** Allow defining structure fields in a single request for efficiency.
    *   **Ghidra Cmd:** Uses existing structure creation logic plus `StructureDataType.add/insert` API calls on the backend.
    *   **Details:** Modify the existing tool to accept an optional `fields: List[Dict[str, Any]]` parameter. Update backend endpoint `/dataTypes/createStructure` to process this list.
    *   **Status:** Completed. Enhanced the existing `create_structure_data_type` tool to accept an optional `fields` parameter, implemented `createStructureDataTypeWithFields` backend method, and modified the handler to detect and process field definitions.

3.  **New Tool: `rename_structure_field`**
    *   **Goal:** Allow renaming fields within existing structures.
    *   **Ghidra Cmd:** `ghidra.app.cmd.data.RenameDataFieldCmd`
    *   **Details:** Create tool `rename_structure_field(structure_name: str, old_field_name: str, new_field_name: str)` calling a new backend endpoint.
    *   **Status:** Completed. Implemented new `rename_structure_field` tool in Python bridge, created `/dataTypes/renameStructureField` endpoint, and implemented `renameStructureField` service method in DataTypeService that handles field deletion and re-insertion to preserve field attributes.

4.  **Modify Tool: `create_enum_data_type`**
    *   **Goal:** Fix the backend bug (`EnumDB` cast error) preventing enum creation.
    *   **Ghidra Cmd:** N/A (Requires backend Java code debugging).
    *   **Details:** Investigate and fix the Java implementation for the `/dataTypes/createEnum` endpoint.
    *   **Status:** Completed. Fixed casting issue by using the `Enum` interface instead of the specific `EnumDataType` implementation class, which resolves the `ClassCastException` when attempting to cast an `EnumDB` to `EnumDataType`.

## Phase 2: Enhancing C++ RE Capabilities

5.  **New Tool: `fill_out_structure`**
    *   **Goal:** Leverage Ghidra's analysis to automatically populate structure fields based on usage. Highly valuable for C++.
    *   **Ghidra Cmd:** `ghidra.app.decompiler.util.FillOutStructureCmd`
    *   **Details:** Create tool `fill_out_structure(function_address: str, variable_identifier: str)` calling a new backend endpoint.
    *   **Status:** Completed. The Python bridge tool has been implemented, backend service method added to DecompileService, and HTTP endpoint created to expose the functionality. The tool uses the function address and variable identifier to leverage Ghidra's FillOutStructureCmd to automatically populate structure fields based on usage in the function.

6.  **New Tool: `delete_structure_field`**
    *   **Goal:** Allow removing fields from structures.
    *   **Ghidra Cmd:** N/A (Requires backend API like `StructureDataType.delete()`).
    *   **Details:** Create tool `delete_structure_field(structure_name: str, field_name: str = None, field_ordinal: int = None)` calling a new backend endpoint.
    *   **Status:** Not started.

7.  **New Tool: `set_structure_field_data_type`**
    *   **Goal:** Allow changing the data type of existing structure fields.
    *   **Ghidra Cmd:** N/A (Requires backend API like `StructureDataType.replace()`).
    *   **Details:** Create tool `set_structure_field_data_type(structure_name: str, field_name: str, new_data_type_name: str)` calling a new backend endpoint.
    *   **Status:** Not started.

8.  **New Tool: `apply_function_data_types`**
    *   **Goal:** Automatically propagate defined types to function signatures based on analysis.
    *   **Ghidra Cmd:** `ghidra.app.cmd.function.ApplyFunctionDataTypesCmd`
    *   **Details:** Create tool `apply_function_data_types(function_address: str)` calling a new backend endpoint.
    *   **Status:** Completed. Implemented applyFunctionDataTypes method in FunctionPrototypeService, created HTTP handler endpoint, and added the Python bridge function. The tool allows automatically propagating defined data types to function signatures by leveraging Ghidra's ApplyFunctionDataTypesCmd.

## Phase 3: Further Refinements

9.  **New Tool: `create_namespace`**
    *   **Goal:** Better organization mirroring C++ code structure.
    *   **Ghidra Cmd:** `ghidra.app.cmd.label.CreateNamespacesCmd`
    *   **Details:** Create tool `create_namespace(path: str, source: str = "USER_DEFINED")` calling a new backend endpoint.
    *   **Status:** Completed. Implemented NamespaceService, NamespaceHttpHandler, and NamespaceServiceInitializer with new endpoint `/namespace/create`. Added Python bridge tool `create_namespace()` that accepts a namespace path string and optional source type parameter.

10. **Modify Tool: `set_function_prototype`**
    *   **Goal:** Add explicit support for variadic functions.
    *   **Ghidra Cmd:** `ghidra.app.cmd.function.ApplyFunctionSignatureCmd` + `FunctionDefinition.setVarArgs(True)` on backend.
    *   **Details:** Add `is_variadic: bool = False` parameter. Update backend logic. (Deferring custom storage/`thiscall` improvements).
    *   **Status:** Not started.
