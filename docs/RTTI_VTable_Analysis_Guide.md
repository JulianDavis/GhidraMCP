# Ghidra C++ Class Analysis Guide: Finding Vtables and RTTI Hints

This guide outlines techniques used to identify C++ classes, their virtual function tables (vtables), and relationships within a Ghidra project, focusing on methods applicable even when standard RTTI parsing is difficult (common with older MSVC++ binaries). Examples are drawn from the analysis of the Shadowbane client (`sb.exe`).

## Introduction

In C++, virtual functions enable polymorphism through vtables. Each class with virtual functions (or inheriting from a class with them) typically has an associated vtable – an array of function pointers. Objects of that class contain a hidden pointer (the vptr) to this table. RTTI (Run-Time Type Information) data structures are often linked near the vtable, providing class names and inheritance details, but parsing this can be challenging.

This guide focuses on finding vtables and understanding class structure by analyzing code references and memory layouts.

## 1. Finding Vtables

### Method 1: Tracing References to Known Virtual Functions

If you know or suspect a function is virtual (e.g., a common base class function like `recv` in a socket class, or a destructor), finding where it's referenced can lead to its vtable entry.

*   **Challenge:** Direct calls might be optimized out or hidden by thunks.
*   **Process:**
    1.  Identify a potential virtual function (e.g., `recv` imported from Winsock).
    2.  Use `get_references` on the function's address. This might lead to wrapper functions within the binary.
        *   *Example:* `get_references` on `recv` (`0x00cd57f4`) led to a call from `0x00510c95` inside `FUN_00510c70` (renamed `AI_ArcBaseSocketImp_Receive`).
    3.  Use `get_references` on the wrapper function (`AI_ArcBaseSocketImp_Receive` at `0x00510c70`).
    4.  If the reference comes from a `JMP` instruction (a thunk), use `get_references` on the *thunk's* address.
        *   *Example:* `get_references` on `0x00510c70` led to a `JMP` thunk at `0x00404a11`.
    5.  Use `get_references` on the thunk (`0x00404a11`). If this reference comes from a data address (e.g., in `.rdata`), that address is likely an entry within a vtable.
        *   *Example:* `get_references` on `0x00404a11` led to a reference from `0x015444d8`. This is the vtable entry for `AI_ArcBaseSocketImp_Receive`.

### Method 2: Finding References to Vtable Pointers (in Constructors/Destructors)

Constructors are responsible for setting the vptr in a new object to point to the class's vtable. Destructors often do the same (resetting to the base class vtable during destruction). Finding where a vtable address is written to memory often identifies constructors or destructors.

*   **Process:**
    1.  Identify a potential vtable start address (see Section 2).
    2.  Use `get_references` on the vtable's start address.
    3.  Examine the functions containing these references using `disassemble_at_address` and `decompile_function`. Look for code that writes the vtable address to the beginning of an object (often pointed to by `ESI` or `ECX` which holds the `this` pointer).
        *   *Example:* `get_references` on `0x015444d0` (start of `ArcBaseSocketImp` vtable) led to `0x0051109d` (inside `ArcBaseSocketImp::ArcBaseSocketImp`) and `0x00511216` (inside `ArcBaseSocketImp::~ArcBaseSocketImp`), confirming the vtable belongs to `ArcBaseSocketImp`.
        *   *Example:* `get_references` on `0x015465b4` (start of `NetworkClientClass???` vtable) led to multiple constructors (`0x0053e6f7`, `0x0053e263`, `0x0053e2f0`, `0x0053e421`, `0x0053e564`) and a destructor (`0x0053e8b6`).

## 2. Analyzing Vtables and RTTI Hints

Once you suspect you've found a vtable entry or start address:

*   **Examine Memory:** Use `memory_read` around the suspected vtable address.
    *   **Look for Function Pointers:** Vtables are primarily arrays of code addresses.
    *   **Look for RTTI Pointer (MSVC++):** Often, the 4 bytes *before* the first virtual function pointer contain a pointer to an `RTTICompleteObjectLocator` structure, which itself points to other RTTI data (like type descriptors containing class names). This pointer usually points somewhere within the `.rdata` or `.data` sections.
        *   *Example:* At `0x015444cc` (4 bytes before the suspected start `0x015444d0` of the `ArcBaseSocketImp` vtable), we found `0x0158e4a0`, likely the RTTI locator pointer. *Note: Fully parsing RTTI structures manually or with scripts can be complex.*
    *   **Identify Vtable Start:** The actual vtable usually starts immediately after the RTTI locator pointer (if present).
        *   *Example:* Based on the RTTI pointer at `0x015444cc`, the `ArcBaseSocketImp` vtable starts at `0x015444d0`.
*   **Analyze Vtable Functions:** Decompile the functions pointed to by the vtable entries. These are the virtual methods of the class. Analyzing them helps understand the class's behavior.
    *   *Example:* We decompiled functions pointed to by the `NetworkClientClass???` vtable (`0x015465b4`), such as `0x0040aeac` (thunk for `NetworkClientClass???::virtual_method_2???`).

## 3. Identifying Class Hierarchy and Relationships

*   **Analyze Constructors:**
    *   **Member Initialization:** Look for writes to memory relative to the `this` pointer (`ECX` or `ESI`). This reveals member variables, their offsets, and potentially their types based on initialization values or functions called.
        *   *Example:* `ArcBaseSocketImp::ArcBaseSocketImp` initialized members at offsets `0x4` (hostname), `0x14` (port/flags), `0x1c` (socket handle), `0x20` (error flag). `ArcBaseSocketImp::ArcBaseSocketImp_2` initialized offset `0x18` (numeric IP).
    *   **Base Class Constructor Calls:** Constructors often call base class constructors near the beginning.
        *   *Example:* All identified constructors called `thunk_FUN_0053f7d0`, suggesting it might be a common base class constructor or initializer.
    *   **Composition:** Constructors might allocate memory (`operator_new`) and call constructors of other classes to create member objects.
        *   *Example:* `NetworkClientClass???` constructors allocated memory and called `ArcBaseSocketImp` or `SocketContainerClass??` constructors, storing the result pointer as a member.
*   **Analyze Destructors:**
    *   **Member Cleanup:** Look for calls to `operator delete` or destructors of member objects.
    *   **Base Class Destructor Calls:** Destructors often call base class destructors near the end.
        *   *Example:* `ArcBaseSocketImp::~ArcBaseSocketImp` called `thunk_FUN_0053f840`.
    *   **Virtual Destructor Calls:** Look for indirect calls like `(*(code *)**(undefined4 **)member_ptr)(1);`. This pattern often indicates calling a virtual destructor on a member or base class pointer.
        *   *Example:* `NetworkClientClass???::~NetworkClientClass???` called the virtual destructor for the object at offset `0xC`.
*   **Analyze Virtual Methods:** Decompiling virtual methods reveals the class's polymorphic behavior. Look for accesses to member variables and calls to other methods (virtual or non-virtual).
    *   *Example:* `NetworkClientClass???` virtual methods often called other virtual methods within the same class, indicating internal dispatching or processing logic.

## 4. Handling Thunks (JMP Tables)

We frequently encountered function pointers (in vtables or direct calls) that pointed not to the actual function start, but to a simple `JMP` instruction that then jumped to the real function.

*   **Identification:** Disassembling the target address reveals a `JMP` instruction.
*   **Process:** When a reference leads to a `JMP`, you must analyze the `JMP` target address to find the actual function code. Use `get_references` on the *thunk's address* to find where it's used (e.g., in vtables or call instructions).
    *   *Example:* The `recv` wrapper `AI_ArcBaseSocketImp_Receive` was referenced via the thunk `0x00404a11`. Its constructors were referenced via thunks `0x0040650f` and `0x00427fbb`. Many `NetworkClientClass???` virtual methods were also referenced via thunks.

## Conclusion

Reconstructing C++ classes in Ghidra, especially from older compilers without perfect RTTI recovery, involves an iterative process:

1.  Start with a known function or data reference (like an imported function or a string).
2.  Follow references (`get_references`).
3.  Analyze code (`disassemble_at_address`, `decompile_function`) and memory (`memory_read`).
4.  Identify patterns related to constructors, destructors, vtable assignments, and virtual calls.
5.  Look for thunks (`JMP` instructions) and follow them.
6.  Use logging strings and function parameters/return values as hints for class names and method purposes.
7.  Define structures (`create_structure_data_type`, `add_field_to_structure`) and rename functions/variables as you gain understanding.

By combining these techniques, you can gradually piece together the class structure and behavior even when automated tools fall short.
