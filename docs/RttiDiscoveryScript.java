// Ghidra script to identify and parse MSVC RTTI structures (32-bit focus).
// @author Roo
// @category C++
// @keybinding
// @menupath
// @toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.Scalar; // Added import
import ghidra.app.util.demangler.Demangler; // Keep for DemangledObject type hint if needed elsewhere, though DemanglerUtil is static
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil; // Use the static utility class
// Removed DemanglerFactory, DemanglerOptions, DemanglerParseException
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import java.util.List; // Needed for the return type of DemanglerUtil.demangle

import java.util.*;
import java.io.IOException; // Added for MemoryBuffer methods

public class RttiDiscoveryScript extends GhidraScript {

    private static final String RTTI_LOCATOR_SIGNATURE = "_s__RTTICompleteObjectLocator";
    private static final String RTTI_HIERARCHY_SIGNATURE = "_s__RTTIClassHierarchyDescriptor";
    private static final String RTTI_BASE_CLASS_SIGNATURE = "_s__RTTIBaseClassDescriptor";
    private static final String TYPE_DESCRIPTOR_SIGNATURE = "TypeDescriptor"; // Based on Ghidra's built-in

    private static final String MSVC_CLASS_MANGLE_PREFIX = ".?AV";

    private DataTypeManager dtm;
    private Listing listing;
    private Memory memory;
    private AddressFactory addrFactory;
    private SymbolTable symbolTable;
    private int pointerSize;

    private StructureDataType locatorDt;
    private StructureDataType hierarchyDt;
    private StructureDataType baseClassDt;
    private StructureDataType typeDescDt; // Use built-in or define if needed
    private PointerDataType pointerDt;

    private Set<Address> processedLocators = new HashSet<>();

    @Override
    protected void run() throws Exception {
        dtm = currentProgram.getDataTypeManager();
        listing = currentProgram.getListing();
        memory = currentProgram.getMemory();
        addrFactory = currentProgram.getAddressFactory();
        symbolTable = currentProgram.getSymbolTable();
        pointerSize = currentProgram.getDefaultPointerSize();
        pointerDt = PointerDataType.dataType; // Default pointer

        println("Starting MSVC RTTI Discovery Script...");

        // 1. Define RTTI Structures if they don't exist
        if (!defineRttiStructures()) {
            printerr("Failed to define necessary RTTI structures. Aborting.");
            return;
        }

        // 2. Ask user for the memory range to scan
        Address startAddress = null;
        Address endAddress = null;
        try {
             startAddress = askAddress("Scan Start Address", "Enter the starting address for RTTI scan:");
             endAddress = askAddress("Scan End Address", "Enter the ending address for RTTI scan (inclusive):");
        } catch (CancelledException e) {
             println("Script cancelled by user.");
             return;
        } catch (IllegalArgumentException e) {
             printerr("Invalid address entered: " + e.getMessage());
             return;
        }

        if (startAddress == null || endAddress == null || startAddress.compareTo(endAddress) > 0) {
            printerr("Invalid address range provided. Start address must be less than or equal to end address.");
            return;
        }

        println("Scanning range: " + startAddress + " - " + endAddress);

        // 3. Scan for potential Locator pointers
        // Heuristic: Look for pointers P where P points to L (a potential Locator)
        // and L+12 points to T (a potential TypeDescriptor) which has a valid name.
        // A common pattern is that the pointer *to* the locator is at VTABLE_ADDR - pointerSize.
        AddressSetView scanSet = new AddressSet(startAddress, endAddress);
        // It's generally better to iterate addresses and check data, rather than iterating defined data,
        // as RTTI pointers might not always be pre-defined as pointers.
        // However, iterating all addresses is slow. Let's stick with defined data for now,
        // but acknowledge this limitation. A more robust script might scan memory directly.
        DataIterator definedDataIterator = listing.getDefinedData(scanSet, true); // Iterate defined data items

        monitor.initialize(scanSet.getNumAddresses() / pointerSize); // Rough estimate
        monitor.setMessage("Scanning for RTTI Locators...");

        while (definedDataIterator.hasNext() && !monitor.isCancelled()) {
            Data vtablePtrData = definedDataIterator.next();
            Address vtablePtrAddr = vtablePtrData.getAddress(); // Get address from the Data object
            monitor.incrementProgress(1);

            // Already have vtablePtrData from the iterator
            if (!vtablePtrData.isPointer()) {
                 continue; // Ensure it's actually a pointer type
            }

            // Assume vtable starts here, check address before it for locator pointer
            Address potentialLocatorPtrAddr = vtablePtrAddr.subtractWrap(pointerSize);
            if (!memory.contains(potentialLocatorPtrAddr)) continue; // Check bounds

            Address locatorAddr = getPointerAt(potentialLocatorPtrAddr);
            if (locatorAddr == null || processedLocators.contains(locatorAddr)) {
                continue; // Invalid pointer or already processed
            }

            // Validate the potential locator
            if (isValidLocator(locatorAddr, monitor)) {
                println("Found potential RTTI Locator at: " + locatorAddr + " (referenced near " + vtablePtrAddr + ")");
                try {
                    processRttiLocator(locatorAddr, vtablePtrAddr, monitor);
                    processedLocators.add(locatorAddr);
                } catch (Exception e) {
                    printerr("Error processing locator at " + locatorAddr + ": " + e.getMessage());
                }
            }
             monitor.checkCancelled(); // Check more frequently during validation
        }

        println("RTTI Discovery finished. Found " + processedLocators.size() + " locators.");
    }

    // --- Structure Definition ---

    private boolean defineRttiStructures() throws CancelledException {
        int transactionID = currentProgram.startTransaction("Define RTTI Types");
        boolean success = false;
        try {
            // --- TypeDescriptor (Check if Ghidra's built-in exists and is suitable) ---
            typeDescDt = findStructure(TYPE_DESCRIPTOR_SIGNATURE);
            if (typeDescDt == null) {
                 // Define basic TypeDescriptor if not found (Ghidra often has one)
                 // Note: The 'name' field is variable length, handled during application.
                 typeDescDt = new StructureDataType(new CategoryPath("/RTTI"), TYPE_DESCRIPTOR_SIGNATURE, 0);
                 typeDescDt.add(pointerDt, "pVFTable", "Pointer to type_info vftable");
                 typeDescDt.add(DWordDataType.dataType, "spare", "Typically NULL");
                 // name[0] is implicit
                 dtm.addDataType(typeDescDt, DataTypeConflictHandler.REPLACE_HANDLER);
                 println("Defined basic TypeDescriptor structure.");
            } else {
                 println("Using existing TypeDescriptor structure.");
            }


            // --- RTTICompleteObjectLocator ---
            locatorDt = findStructure(RTTI_LOCATOR_SIGNATURE);
            if (locatorDt == null) {
                locatorDt = new StructureDataType(new CategoryPath("/RTTI"), RTTI_LOCATOR_SIGNATURE, 0);
                locatorDt.add(DWordDataType.dataType, "signature", "Usually 0 or 1 (x64)");
                locatorDt.add(DWordDataType.dataType, "offset", "vtable offset in class");
                locatorDt.add(DWordDataType.dataType, "cdOffset", "constructor displacement offset");
                locatorDt.add(pointerDt, "pTypeDescriptor", "-> TypeDescriptor");
                locatorDt.add(pointerDt, "pClassHierarchyDescriptor", "-> ClassHierarchyDescriptor");
                // locatorDt.add(pointerDt, "pSelf", "-> this locator (optional, x64?)"); // Add if needed
                dtm.addDataType(locatorDt, DataTypeConflictHandler.REPLACE_HANDLER);
                println("Defined " + RTTI_LOCATOR_SIGNATURE);
            }

            // --- RTTIClassHierarchyDescriptor ---
            hierarchyDt = findStructure(RTTI_HIERARCHY_SIGNATURE);
            if (hierarchyDt == null) {
                hierarchyDt = new StructureDataType(new CategoryPath("/RTTI"), RTTI_HIERARCHY_SIGNATURE, 0);
                hierarchyDt.add(DWordDataType.dataType, "signature", "Usually 0");
                hierarchyDt.add(DWordDataType.dataType, "attributes", "Bit 0: MI, Bit 1: VI");
                hierarchyDt.add(DWordDataType.dataType, "numBaseClasses", "Number of base class descriptors");
                hierarchyDt.add(pointerDt, "pBaseClassArray", "-> array of pointers to BaseClassDescriptors");
                dtm.addDataType(hierarchyDt, DataTypeConflictHandler.REPLACE_HANDLER);
                println("Defined " + RTTI_HIERARCHY_SIGNATURE);
            }

            // --- RTTIBaseClassDescriptor ---
            baseClassDt = findStructure(RTTI_BASE_CLASS_SIGNATURE);
            if (baseClassDt == null) {
                baseClassDt = new StructureDataType(new CategoryPath("/RTTI"), RTTI_BASE_CLASS_SIGNATURE, 0);
                baseClassDt.add(pointerDt, "pTypeDescriptor", "-> TypeDescriptor of base class");
                baseClassDt.add(DWordDataType.dataType, "numContainedBases", "Number of direct bases of this base");

                // PMD structure (Pointer-to-member displacement)
                StructureDataType pmdDt = new StructureDataType("PMD", 0);
                pmdDt.add(IntegerDataType.dataType, "mdisp", "Member displacement");
                pmdDt.add(IntegerDataType.dataType, "pdisp", "Vbtable displacement (-1 = non-virtual)");
                pmdDt.add(IntegerDataType.dataType, "vdisp", "Displacement inside vbtable");
                baseClassDt.add(pmdDt, "PMD", "Pointer-to-member displacement info");

                baseClassDt.add(DWordDataType.dataType, "attributes", "Flags describing inheritance");
                baseClassDt.add(pointerDt, "pClassDescriptor", "-> Base class's ClassHierarchyDescriptor");
                dtm.addDataType(baseClassDt, DataTypeConflictHandler.REPLACE_HANDLER);
                println("Defined " + RTTI_BASE_CLASS_SIGNATURE);
            }
            success = true;
        } finally {
            currentProgram.endTransaction(transactionID, success);
        }
        return success;
    }

     private StructureDataType findStructure(String name) {
        DataType dt = dtm.getDataType("/RTTI/" + name);
        if (dt instanceof StructureDataType) {
            return (StructureDataType) dt;
        }
        // Check root category as well
        dt = dtm.getDataType("/" + name);
         if (dt instanceof StructureDataType) {
            return (StructureDataType) dt;
        }
        return null;
    }

    // --- Validation ---

    private boolean isValidLocator(Address locatorAddr, TaskMonitor monitor) {
        try {
            monitor.checkCancelled();
            // Basic checks: is pointer valid and within memory?
            if (locatorAddr == null || !memory.contains(locatorAddr)) return false;

            // Read potential TypeDescriptor pointer
            Address tdAddr = getPointerAt(locatorAddr.add(12)); // offsetof(pTypeDescriptor) = 12
            if (tdAddr == null || !memory.contains(tdAddr)) return false;

            // Read potential HierarchyDescriptor pointer
            Address hierAddr = getPointerAt(locatorAddr.add(16)); // offsetof(pClassHierarchyDescriptor) = 16
            // Hierarchy can be NULL, but if not NULL, it must be a valid address
            if (hierAddr != null && !memory.contains(hierAddr)) return false;

            // Validate TypeDescriptor
            return isValidTypeDescriptor(tdAddr, monitor);

        } catch (MemoryAccessException | CancelledException e) {
            // Ignore memory access errors during validation
            return false;
        }
    }

    private boolean isValidTypeDescriptor(Address tdAddr, TaskMonitor monitor) throws MemoryAccessException, CancelledException {
         monitor.checkCancelled();
         if (tdAddr == null || !memory.contains(tdAddr)) return false;

         // Check pVFTable (optional but good heuristic: points to .rdata?)
         Address pVFTable = getPointerAt(tdAddr);
         if (pVFTable == null || !memory.contains(pVFTable)) return false;
         // Could add check: does pVFTable point to a known type_info vtable?

         // Check name
         Address nameAddr = tdAddr.add(8); // offsetof(name) - assuming 32-bit pVFTable and dword spare
         if (!memory.contains(nameAddr)) return false;

         String name = readString(nameAddr, 64); // Read a reasonable length
         if (name == null || !name.startsWith(MSVC_CLASS_MANGLE_PREFIX)) {
             return false;
         }

         return true; // Looks plausible
    }

    // --- Processing ---

    private void processRttiLocator(Address locatorAddr, Address vtableAddrHint, TaskMonitor monitor) throws Exception {
        monitor.checkCancelled();
        println("Processing Locator: " + locatorAddr);

        // Apply Locator Structure
        Data locatorData = createDataIfNotExists(locatorAddr, locatorDt);
        if (locatorData == null) {
             printerr("Failed to apply Locator structure at " + locatorAddr);
             return;
        }
        setPlateComment(locatorAddr, "RTTI Complete Object Locator");
        createBookmark(locatorAddr, "RTTI Locator", "C++ RTTI");

        // Get pointers from Locator
        Address tdAddr = getPointerFromData(locatorData, "pTypeDescriptor");
        Address hierAddr = getPointerFromData(locatorData, "pClassHierarchyDescriptor");

        // Process TypeDescriptor
        String className = processTypeDescriptor(tdAddr, monitor);
        if (className == null) {
             printerr("Failed to process TypeDescriptor at " + tdAddr + " for locator " + locatorAddr);
             return; // Cannot proceed without class name
        }
        String demangledName = demangle(className, tdAddr); // Pass context address
        String labelName = "RTTI_Locator_" + demangledName;
        createLabel(locatorAddr, labelName, true, SourceType.ANALYSIS);
        setEOLComment(locatorAddr, demangledName);


        // Process Hierarchy (if present)
        if (hierAddr != null && !hierAddr.equals(Address.NO_ADDRESS)) {
            processHierarchyDescriptor(hierAddr, className, demangledName, monitor);
        } else {
             println("  - No ClassHierarchyDescriptor found for " + demangledName);
        }

        // Optional: Try to label the vtable pointer and vtable itself
        Address potentialLocatorPtrAddr = vtableAddrHint.subtractWrap(pointerSize);
        if (getPointerAt(potentialLocatorPtrAddr) != null && getPointerAt(potentialLocatorPtrAddr).equals(locatorAddr)) {
             createLabel(potentialLocatorPtrAddr, "RTTI_LocatorPtr_" + demangledName, false, SourceType.ANALYSIS);
             setEOLComment(potentialLocatorPtrAddr, "-> " + labelName);
             createLabel(vtableAddrHint, "vtable_" + demangledName, true, SourceType.ANALYSIS);
             setPlateComment(vtableAddrHint, "VTable for " + demangledName);
        } else {
            println("  - Could not definitively link locator to vtable at " + vtableAddrHint);
        }
    }

    private String processTypeDescriptor(Address tdAddr, TaskMonitor monitor) throws Exception {
         monitor.checkCancelled();
         if (tdAddr == null || !memory.contains(tdAddr)) return null;

         // Apply TypeDescriptor Structure (fixed part)
         Data tdData = createDataIfNotExists(tdAddr, typeDescDt); // Apply base structure
         if (tdData == null) return null;

         setPlateComment(tdAddr, "RTTI Type Descriptor");
         createBookmark(tdAddr, "RTTI TypeDescriptor", "C++ RTTI");


         // Read and define the name string
         Address nameAddr = tdAddr.add(8); // Offset of name field
         Data nameData = listing.getDefinedDataAt(nameAddr);
         String name = null;
         if (nameData != null && nameData.getDataType() instanceof TerminatedStringDataType) {
             name = (String) nameData.getValue();
         } else {
             // If not defined as a string, try reading it directly
             name = readString(nameAddr, 256); // Read up to 256 chars
             if (name != null) {
                 // Attempt to create the string data type now that we know the length
                 try {
                     // Use the more robust clearCodeUnits
                     // Calculate end address for clearing (inclusive)
                     Address nameEndAddr = nameAddr.add(name.length());
                     // Clear the exact range needed for the string + null terminator
                     listing.clearCodeUnits(nameAddr, nameEndAddr, false, monitor);
                     // Create the string data type
                     listing.createData(nameAddr, TerminatedStringDataType.dataType, name.length() + 1);
                 } catch (Exception e) {
                     // Log error but continue, we already read the name
                     printerr("Could not define string data type at " + nameAddr + ", but read value: " + e.getMessage());
                 }
             } else {
                  printerr("Failed to read string at " + nameAddr);
                  return null; // Cannot get name
             }
         }

         if (name == null || !name.startsWith(MSVC_CLASS_MANGLE_PREFIX)) {
             printerr("Invalid or non-MSVC class name found at " + nameAddr);
             return null;
         }

         String demangledName = demangle(name, nameAddr);
         createLabel(tdAddr, "RTTI_TypeDescriptor_" + demangledName, true, SourceType.ANALYSIS);
         setEOLComment(tdAddr, demangledName);
         setEOLComment(nameAddr, demangledName);


         return name; // Return mangled name
    }

     private void processHierarchyDescriptor(Address hierAddr, String mangledClassName, String demangledClassName, TaskMonitor monitor) throws Exception {
        monitor.checkCancelled();
        println("  - Processing Hierarchy: " + hierAddr + " for " + demangledClassName);

        Data hierData = createDataIfNotExists(hierAddr, hierarchyDt);
        if (hierData == null) return;
        setPlateComment(hierAddr, "RTTI Class Hierarchy Descriptor for " + demangledClassName);
        createBookmark(hierAddr, "RTTI Hierarchy", "C++ RTTI");
        createLabel(hierAddr, "RTTI_Hierarchy_" + demangledClassName, true, SourceType.ANALYSIS);

        int numBaseClasses = getIntFromData(hierData, "numBaseClasses");
        Address baseArrayAddr = getPointerFromData(hierData, "pBaseClassArray");

        if (baseArrayAddr == null || numBaseClasses <= 0) {
            println("    - No base classes listed or invalid array pointer.");
            return;
        }

        println("    - numBaseClasses: " + numBaseClasses);
        println("    - pBaseClassArray: " + baseArrayAddr);

        // Define the array of pointers
        ArrayDataType basePtrArrayDt = new ArrayDataType(pointerDt, numBaseClasses, pointerSize);
        Data baseArrayData = createDataIfNotExists(baseArrayAddr, basePtrArrayDt);
        if (baseArrayData == null) {
             printerr("    - Failed to apply base pointer array at " + baseArrayAddr);
             return;
        }
        createLabel(baseArrayAddr, "RTTI_BaseArray_" + demangledClassName, true, SourceType.ANALYSIS);


        // Process each base class descriptor
        for (int i = 0; i < numBaseClasses; i++) {
            monitor.checkCancelled();
            Data elementData = baseArrayData.getComponent(i);
            Address baseDescAddr = (Address) elementData.getValue();

            if (baseDescAddr == null || !memory.contains(baseDescAddr)) {
                printerr("    - Invalid BaseClassDescriptor pointer at index " + i + " (" + elementData.getAddress() + ")");
                continue;
            }

            setEOLComment(elementData.getAddress(), "-> BaseClassDescriptor[" + i + "]");
            processBaseClassDescriptor(baseDescAddr, i, demangledClassName, monitor);
        }
    }

    private void processBaseClassDescriptor(Address baseDescAddr, int index, String containingClassName, TaskMonitor monitor) throws Exception {
        monitor.checkCancelled();
        println("      - Processing BaseClassDescriptor[" + index + "]: " + baseDescAddr);

        Data baseDescData = createDataIfNotExists(baseDescAddr, baseClassDt);
        if (baseDescData == null) return;

        createBookmark(baseDescAddr, "RTTI BaseClassDescriptor", "C++ RTTI");
        String baseLabelSuffix = containingClassName + "_Base" + index;
        createLabel(baseDescAddr, "RTTI_BaseDesc_" + baseLabelSuffix, true, SourceType.ANALYSIS);


        Address baseTdAddr = getPointerFromData(baseDescData, "pTypeDescriptor");
        String baseClassNameMangled = processTypeDescriptor(baseTdAddr, monitor); // Process nested TypeDescriptor

        if (baseClassNameMangled != null) {
             String baseClassNameDemangled = demangle(baseClassNameMangled, baseTdAddr); // Pass context address
             setEOLComment(baseDescAddr, "Base[" + index + "]: " + baseClassNameDemangled);
             setEOLComment(baseDescData.getComponent(0).getAddress(), "-> TypeDescriptor for " + baseClassNameDemangled); // Comment the pTypeDescriptor field

             // TODO: Add logic here to store/represent the inheritance relationship
             // e.g., Add comment to derived class structure, or build an external map
             // Need PMD.mdisp, PMD.pdisp, attributes for full picture
             Data pmdData = baseDescData.getComponent(2); // Assuming PMD is the 3rd component (index 2)
             int mdisp = getIntFromData(pmdData, "mdisp");
             int pdisp = getIntFromData(pmdData, "pdisp");
             int attributes = getIntFromData(baseDescData, "attributes"); // Assuming attributes is 4th component (index 3)

             String inheritanceType = (pdisp == -1) ? "Non-Virtual" : "Virtual";
             println("        - Base Class: " + baseClassNameDemangled +
                       ", Offset (mdisp): " + mdisp +
                       ", Type: " + inheritanceType +
                       ", Attrs: 0x" + Integer.toHexString(attributes));

        } else {
             setEOLComment(baseDescAddr, "Base[" + index + "]: <Error Parsing TypeDesc>");
        }

        // Optionally, recursively process baseDescData->pClassDescriptor if needed for deeper hierarchy
    }


    // --- Ghidra API Helpers ---

private Address getPointerAt(Address addr) {
    try {
        if (addr == null || !memory.contains(addr)) {
            return null;
        }
        byte[] bytes = new byte[pointerSize];
        int bytesRead = memory.getBytes(addr, bytes);
        if (bytesRead != pointerSize) {
            printerr("Could not read full pointer (" + pointerSize + " bytes) at " + addr);
            return null;
        }

        long offset = bytesToLong(bytes, pointerSize, memory.isBigEndian());
        // Use the same address space as the address we read from,
        // unless the pointer represents an offset in a different space (more complex case).
        return addr.getAddressSpace().getAddress(offset);

    } catch (MemoryAccessException e) {
        printerr("Memory access error reading pointer at " + addr + ": " + e.getMessage());
        return null;
    }
}

// Helper to convert byte array to long based on endianness
private long bytesToLong(byte[] bytes, int size, boolean bigEndian) {
    long value = 0;
    if (bigEndian) {
        for (int i = 0; i < size; i++) {
            value = (value << 8) + (bytes[i] & 0xff);
        }
    } else {
        for (int i = size - 1; i >= 0; i--) {
            value = (value << 8) + (bytes[i] & 0xff);
        }
    }
    return value;
}

     private Address getPointerFromData(Data containerData, String fieldName) {
        DataTypeComponent component = getComponentByName(containerData, fieldName);
        if (component == null) return null;

        try {
            Data fieldData = containerData.getComponent(component.getOrdinal());
            if (fieldData != null && fieldData.isPointer()) {
                return (Address) fieldData.getValue();
            }
             // If not defined as pointer, try reading from memory at component offset
             Address fieldAddr = containerData.getAddress().add(component.getOffset());
             return getPointerAt(fieldAddr);
        } catch (Exception e) {
             printerr("Error getting pointer field '" + fieldName + "' from " + containerData.getAddress() + " at offset " + component.getOffset() + ": " + e.getMessage());
        }
        return null;
    }

     private int getIntFromData(Data containerData, String fieldName) {
         DataTypeComponent component = getComponentByName(containerData, fieldName);
         if (component == null) return -1; // Or throw

         try {
            Data fieldData = containerData.getComponent(component.getOrdinal());
            if (fieldData != null && fieldData.getValue() instanceof Scalar) {
                 return (int) ((Scalar) fieldData.getValue()).getSignedValue(); // Use getSignedValue or getUnsignedValue as appropriate
            }
             // If not defined, try reading from memory
             Address fieldAddr = containerData.getAddress().add(component.getOffset());
             if (component.getDataType().isEquivalent(DWordDataType.dataType) || component.getDataType().isEquivalent(IntegerDataType.dataType)) {
                 return memory.getInt(fieldAddr);
             } else if (component.getDataType().isEquivalent(WordDataType.dataType)) {
                 return memory.getShort(fieldAddr);
             } // Add other integer types if needed
         } catch (Exception e) {
              printerr("Error getting int field '" + fieldName + "' from " + containerData.getAddress() + " at offset " + component.getOffset() + ": " + e.getMessage());
         }
         return -1; // Sentinel
     }

     // Helper to get component by name
     private DataTypeComponent getComponentByName(Data containerData, String fieldName) {
         DataType dt = containerData.getBaseDataType();
         if (!(dt instanceof Structure)) {
             printerr("Cannot get component '" + fieldName + "' from non-structure data at " + containerData.getAddress());
             return null;
         }
         Structure struct = (Structure) dt;
         for (DataTypeComponent comp : struct.getComponents()) {
             if (fieldName.equals(comp.getFieldName())) {
                 return comp;
             }
         }
         printerr("Component '" + fieldName + "' not found in structure " + struct.getName() + " at " + containerData.getAddress());
         return null;
     }


    private String readString(Address addr, int maxLength) {
        try {
            byte[] bytes = new byte[maxLength];
            int bytesRead = memory.getBytes(addr, bytes);
            if (bytesRead <= 0) {
                return null; // Nothing read
            }

            int len = 0;
            while (len < bytesRead && bytes[len] != 0) {
                len++;
            }
            // Use platform default charset, or specify one like StandardCharsets.US_ASCII if appropriate
            return new String(bytes, 0, len);

        } catch (MemoryAccessException e) {
            printerr("Failed to read string bytes at " + addr + ": " + e.getMessage());
            return null;
        }
    }

    private Data createDataIfNotExists(Address addr, DataType dt) {
        if (addr == null || dt == null) {
            printerr("Invalid address or data type provided to createDataIfNotExists.");
            return null;
        }

        int length = dt.getLength();
        // Ensure we have a valid length for fixed-size types (like our RTTI structs)
        if (length <= 0 && dt instanceof Structure) {
             length = ((Structure)dt).getLength();
        }
        // Array lengths are also fixed
        else if (length <= 0 && dt instanceof Array) {
             length = ((Array)dt).getLength();
        }


        if (length <= 0) {
             // Cannot reliably check/clear/create without a known fixed length.
             // This shouldn't happen for the RTTI structs defined earlier.
             printerr("Cannot determine fixed length for data type " + dt.getName() + " at " + addr + ". Skipping creation.");
             return null;
        }

        // 1. Check if the *correct* data already exists
        Data existingData = listing.getDataAt(addr);
        if (existingData != null && existingData.getDataType().isEquivalent(dt) && existingData.getLength() == length) {
            //println("Data of type " + dt.getName() + " already exists correctly at " + addr);
            return existingData; // Perfect match, nothing to do.
        }

        // 2. If we reach here, either no data exists at addr, or it's the wrong type/size.
        // We need to clear the area required by the *new* data type before creating it.
        try {
            Address endAddr = addr.add(length - 1);
            // Check if *any* code unit exists within the target range before clearing
            AddressSet rangeToClear = new AddressSet(addr, endAddr);
            println("Clearing range " + addr + " to " + endAddr + " before creating " + dt.getName());
            listing.clearCodeUnits(addr, endAddr, false, monitor);
        } catch (Exception e) {
            printerr("Address overflow calculating range for " + dt.getName() + " at " + addr + " with length " + length);
            return null; // Cannot safely clear or create
        }

        // 3. Attempt to create the data
        try {
            Data newData = listing.createData(addr, dt);
            //println("Created data " + dt.getName() + " at " + addr);
            return newData;
        } catch (Exception e) {
            // This is the most likely error if clearing failed or wasn't possible
            printerr("Failed to create data " + dt.getName() + " at " + addr + " (Exception): " + e.getMessage());
            // Provide more context about what might be there
            CodeUnit conflict = listing.getCodeUnitContaining(addr); // Check start addr
            if (conflict == null) conflict = listing.getCodeUnitAt(addr); // Check exact addr
            if (conflict != null) {
                 printerr("  -> Conflicting unit at " + conflict.getAddress() + ": " + conflict.toString());
            } else {
                 printerr("  -> Conflict details unavailable, possibly overlapping existing unit.");
            }
            return null;
        }
    }

    private boolean isUndefined(DataType dt) {
        return dt instanceof Undefined || dt.getName().toLowerCase().contains("undefined");
    }


    // Simple demangler call
    // Demangles a string using the context of an address, required for newer Ghidra versions.
    private String demangle(String mangled, Address contextAddr) {
        if (mangled == null) {
            return "<null_mangled>";
        }
        if (contextAddr == null) {
             printerr("Demangling requires a context address, but none was provided for: " + mangled);
             return cleanupMangledName(mangled); // Fallback
        }

        try {
            // Use the recommended DemanglerUtil method
            List<DemangledObject> results = DemanglerUtil.demangle(currentProgram, mangled, contextAddr);

            if (results != null && !results.isEmpty()) {
                // Typically, for a type name, we expect one primary result.
                DemangledObject demangledObject = results.get(0); // Get the first result

                if (demangledObject != null) {
                    // Prefer the demangled name if available and different from original
                    String name = demangledObject.getName();
                    if (name != null && !name.isBlank() && !name.equals(mangled)) {
                        return cleanupDemangledName(name);
                    }
                    // Fallback to the signature if name is empty or unchanged
                    String signature = demangledObject.getSignature(false); // false = don't include namespace
                    if (signature != null && !signature.isBlank() && !signature.equals(mangled)) {
                         return cleanupDemangledName(signature);
                    }
                }
            }
            // If results are null, empty, or didn't produce a useful name/signature, fall through.
        }
        // Catch specific exceptions if DemanglerUtil throws them, otherwise general Exception
        // Note: DemanglerUtil.demangle itself might not throw DemanglerParseException directly,
        // but underlying operations could. Adjust catch blocks based on actual API behavior if needed.
        catch (Exception e) {
            printerr("Demangling error for '" + mangled + "' at " + contextAddr + ": " + e.getClass().getName() + " - " + e.getMessage() + ". Using basic cleanup.");
        }

        // Fallback: basic cleanup if demangler fails or doesn't change the name
        return cleanupMangledName(mangled);
    }

    // Helper function for basic fallback cleanup (kept from previous version)
    private String cleanupMangledName(String mangled) {
         String cleaned = mangled;
         if (cleaned != null) {
             if (cleaned.startsWith(".?AV")) {
                 cleaned = cleaned.substring(4); // Remove ".?AV"
             }
             cleaned = cleaned.replace("@@", ""); // Remove "@@"
         }
         return cleaned;
    }

    // Helper function to clean common artifacts from demangled names (kept from previous version)
    private String cleanupDemangledName(String demangled) {
        // Remove common MSVC artifacts like backticks or template quotes if needed
        return demangled != null ? demangled.replace("`", "").replace("'", "") : null;
    }
}
