# Ghidra MCP Plugin Enhancement Plan

This document outlines planned improvements for the Ghidra MCP bridge and backend plugin, based on analysis and identified needs during reverse engineering tasks.

## Phase 1: Core Improvements & Addressing Immediate Needs

1.  **New Tool: `set_variable_data_type`**
    *   **Goal:** Allow re-typing local variables in the decompiler view. Addresses the `logContext` issue directly.
    *   **Ghidra Cmd:** `ghidra.app.cmd.function.SetVariableDataTypeCmd`
    *   **Details:** Create tool `set_variable_data_type(function_name: str, variable_name: str, data_type_name: str)` calling a new backend endpoint (`/decompiler/setVariableDataType`). Backend service method needs access to `PluginTool` to execute the command. Requires robust variable and data type lookup.
    *   **Status:** Python tool added, Java service method added (needs PluginTool injection), Java handler added.

2.  **Modify Tool: `create_structure_data_type`**
    *   **Goal:** Allow defining structure fields in a single request for efficiency.
    *   **Ghidra Cmd:** Uses existing structure creation logic plus `StructureDataType.add/insert` API calls on the backend.
    *   **Details:** Modify the existing tool to accept an optional `fields: List[Dict[str, Any]]` parameter. Update backend endpoint `/dataTypes/createStructure` to process this list.
    *   **Status:** Not started.

3.  **New Tool: `rename_structure_field`**
    *   **Goal:** Allow renaming fields within existing structures.
    *   **Ghidra Cmd:** `ghidra.app.cmd.data.RenameDataFieldCmd`
    *   **Details:** Create tool `rename_structure_field(structure_name: str, old_field_name: str, new_field_name: str)` calling a new backend endpoint.
    *   **Status:** Not started.

4.  **Modify Tool: `create_enum_data_type`**
    *   **Goal:** Fix the backend bug (`EnumDB` cast error) preventing enum creation.
    *   **Ghidra Cmd:** N/A (Requires backend Java code debugging).
    *   **Details:** Investigate and fix the Java implementation for the `/dataTypes/createEnum` endpoint.
    *   **Status:** Not started.

## Phase 2: Enhancing C++ RE Capabilities

5.  **New Tool: `fill_out_structure`**
    *   **Goal:** Leverage Ghidra's analysis to automatically populate structure fields based on usage. Highly valuable for C++.
    *   **Ghidra Cmd:** `ghidra.app.decompiler.util.FillOutStructureCmd`
    *   **Details:** Create tool `fill_out_structure(address: str, structure_name: str = None)` calling a new backend endpoint. Investigate command usage details.
    *   **Status:** Not started.

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
    *   **Status:** Not started.

## Phase 3: Further Refinements

9.  **New Tool: `create_namespace`**
    *   **Goal:** Better organization mirroring C++ code structure.
    *   **Ghidra Cmd:** `ghidra.app.cmd.label.CreateNamespacesCmd`
    *   **Details:** Create tool `create_namespace(path: str, source: str = "USER_DEFINED")` calling a new backend endpoint.
    *   **Status:** Not started.

10. **Modify Tool: `set_function_prototype`**
    *   **Goal:** Add explicit support for variadic functions.
    *   **Ghidra Cmd:** `ghidra.app.cmd.function.ApplyFunctionSignatureCmd` + `FunctionDefinition.setVarArgs(True)` on backend.
    *   **Details:** Add `is_variadic: bool = False` parameter. Update backend logic. (Deferring custom storage/`thiscall` improvements).
    *   **Status:** Not started.
