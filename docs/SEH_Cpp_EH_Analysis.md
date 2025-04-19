# Understanding C++ Exception Handling (EH) via SEH in MSVC

This document explains how Microsoft Visual C++ (MSVC) implements C++ exception handling (`try`/`catch`, stack unwinding) using the underlying Windows Structured Exception Handling (SEH) mechanism, and how analyzing these structures aids in reverse engineering C++ binaries.

## SEH Fundamentals

Structured Exception Handling (SEH) is the native Windows mechanism for handling both hardware and software exceptions. Key concepts include:

*   **Exception Records:** Standard structures containing information about an exception (code, flags, address).
*   **Exception Registration:** Functions that need to handle exceptions register a handler function by placing an `_EXCEPTION_REGISTRATION_RECORD` (or similar structure like `_EH3_EXCEPTION_REGISTRATION` for compiler support) onto the stack (x86) or using static unwind info (`.pdata` section on x64). These registrations form a chain.
*   **Exception Dispatching:** When an exception occurs, the system walks the chain of registered handlers, calling each one until a handler chooses to handle the exception (e.g., by executing an `__except` block or performing cleanup and continuing).
*   **Stack Unwinding:** If an exception is handled, the system unwinds the stack, calling registered handlers again (in their cleanup phase) to allow functions to release resources or perform necessary cleanup (like executing `__finally` blocks).

## C++ EH Implementation on top of SEH (MSVC)

MSVC leverages SEH to implement C++ exceptions:

1.  **Throwing:** When `throw SomeObject;` is executed, the compiler typically calls `_CxxThrowException`. This function allocates memory for the exception object (if needed), copies it, and then raises an SEH exception with a specific exception code (e.g., `0xE06D7363`, which is 'msc' followed by 0xE0). It passes information about the thrown object's type (`ThrowInfo`) as parameters within the SEH exception record.
2.  **Catching:** C++ `try`/`catch` blocks are implemented using compiler-generated SEH handlers.
    *   **`_CxxFrameHandler` (and variants):** Functions containing `try`/`catch` or objects needing destruction during unwinding often register a specific C++ EH handler (like `_CxxFrameHandler3` on x86 or use it as the language-specific handler on x64).
    *   **`FuncInfo` Structure:** The compiler generates a static `FuncInfo` structure for each function requiring C++ EH. This structure contains metadata crucial for the `_CxxFrameHandler`. It's typically referenced via the SEH registration frame (x86) or the `.pdata` unwind info (x64).
    *   **Type Matching:** When `_CxxFrameHandler` receives the SEH exception raised by `_CxxThrowException`, it compares the type information from the `ThrowInfo` (passed with the exception) against the types listed in the `FuncInfo`'s `TryBlockMap` for the current scope. If a matching `catch` block is found, the handler signals to the SEH dispatcher that the exception is handled.
    *   **Stack Unwinding & Cleanup:** The `_CxxFrameHandler` also manages stack unwinding for C++ objects. It uses the `UnwindMap` within the `FuncInfo` to determine which cleanup actions (destructor calls via "unwind funclets") need to be executed as the stack unwinds to the handling `catch` block.

## Reverse Engineering Value of C++ EH Structures

Analyzing the `FuncInfo` and related structures provides valuable information beyond RTTI:

*   **`FuncInfo` Location:**
    *   **x86:** Find the SEH registration frame on the stack (often set up by `__SEH_prolog`). The `frameHandler` field points to the function-specific handler, which often loads the address of the `FuncInfo`.
    *   **x64:** Locate the function's entry in the `.pdata` section. The `UnwindInfoAddress` points to an `UNWIND_INFO` structure. If the `Flags` indicate an exception handler (`UNW_FLAG_EHANDLER`), the `ExceptionHandler` field points to the language-specific handler (e.g., `__CxxFrameHandler3`), and the following `ExceptionData` often contains an RVA (Relative Virtual Address) to the `FuncInfo`.
*   **`UnwindMap` (`FuncInfo.pUnwindMap`):**
    *   **Structure:** An array of `_s_UnwindMapEntry` { `int toState; void *action;` }.
    *   **State Transitions:** Describes the cleanup actions needed when unwinding from one state (`current_state`) to another (`toState`). The `state` variable is maintained on the stack (x86, often `[ebp-4]`) or mapped via IP (x64, using `FuncInfo.pIPtoStateMap`). You mentioned seeing MOV instructions saving addresses - these could be updating the state variable or marking boundaries for the IP map.
    *   **Destructor Identification:** The `action` field often points directly to a small "unwind funclet". This funclet's primary job is usually to call the destructor for a specific local object associated with the state transition. Analyzing these funclets is a reliable way to identify class destructors.
*   **`TryBlockMap` (`FuncInfo.pTryBlockMap`):**
    *   **Structure:** An array of `_s_TryBlockMapEntry` describing each `try` block.
    *   **Catch Handlers:** Each entry points to a list of `_s_HandlerType` structures for its associated `catch` blocks.
    *   **`HandlerType` Structure:** Contains flags, offsets, and crucially, a pointer (`pType`) to the `TypeDescriptor` of the exception type being caught. This confirms class types and shows how they are used in error handling.
*   **`ThrowInfo` (`_CxxThrowException` argument):**
    *   **Structure:** Contains flags, pointers to unwind/destroy functions for the thrown object, and a pointer (`pCatchableTypeArray`) to an array of `_s_CatchableType` structures.
    *   **`CatchableTypeArray`:** Lists the types the thrown object can be caught as (its own type plus base types). Each `_s_CatchableType` entry points to the corresponding `TypeDescriptor`, providing another way to link thrown objects to their RTTI.

## Summary for Reverse Engineering

By locating the `FuncInfo` structure for functions (via SEH registration or `.pdata`) and parsing its `UnwindMap` and `TryBlockMap`:

1.  **Identify Destructors:** Analyze the `action` funclets pointed to by the `UnwindMap`.
2.  **Understand Object Lifetimes:** Correlate `UnwindMap` states with code ranges to see where objects requiring cleanup exist.
3.  **Confirm Class Types:** Examine the `TypeDescriptor` pointers within the `TryBlockMap`'s `HandlerType` entries and within the `ThrowInfo` used by `_CxxThrowException`.
4.  **Reconstruct `try`/`catch` Logic:** Map `TryBlockMap` entries back to code ranges and identify the target `catch` blocks.

This analysis provides a dynamic view of object usage and cleanup, complementing the static inheritance information provided by RTTI.
