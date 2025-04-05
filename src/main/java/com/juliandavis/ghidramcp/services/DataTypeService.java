package com.juliandavis.ghidramcp.services;

import com.juliandavis.ghidramcp.core.service.Service;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * Service for creating and managing data types in Ghidra.
 * <p>
 * This service provides methods for creating, managing, and applying various data types
 * including primitives, structures, enums, and arrays.
 */
public class DataTypeService implements Service {

    public static final String SERVICE_NAME = "DataTypeService";
    private Program program;

    /**
     * Get the name of this service.
     *
     * @return the service name
     */
    @Override
    public String getName() {
        return SERVICE_NAME;
    }

    /**
     * Initialize the service with the current program.
     *
     * @param program the current Ghidra program
     */
    @Override
    public void initialize(Program program) {
        this.program = program;
    }

    /**
     * Dispose of any resources used by this service.
     */
    @Override
    public void dispose() {
        this.program = null;
    }

    /**
     * Create a new primitive data type at the specified address
     *
     * @param dataTypeName Name of the data type to create (e.g., "byte", "word", "dword", "qword", "float", "double")
     * @param addressStr   Address where to create the data type
     * @return Map containing the result of the operation
     */
    public Map<String, Object> createPrimitiveDataType(String dataTypeName, String addressStr) {
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return createErrorResponse("Invalid address: " + addressStr);
            }

            // Get the appropriate data type from the built-in types
            DataType dataType = getPrimitiveDataType(dataTypeName);
            if (dataType == null) {
                return createErrorResponse("Unknown or unsupported data type: " + dataTypeName);
            }

            // Create the data
            Data data = program.getListing().createData(address, dataType);
            if (data == null) {
                return createErrorResponse("Failed to create data at address " + addressStr);
            }

            // Create data for the success response
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("address", addressStr);
            responseData.put("dataType", dataTypeName);
            responseData.put("size", data.getLength());
            responseData.put("value", data.getDefaultValueRepresentation());

            // Return standardized success response
            return createSuccessResponse(responseData);
        } catch (Exception e) {
            Msg.error(this, "Error creating primitive data type", e);
            return createErrorResponse("Error creating primitive data type: " + e.getMessage());
        }
    }

    /**
     * Creates a standardized error response with default error code (400)
     *
     * @param errorMessage The error message
     * @return Map representing the error response
     */
    private Map<String, Object> createErrorResponse(String errorMessage) {
        return createErrorResponse(errorMessage, 400);
    }
    
    /**
     * Creates a standardized error response
     * 
     * @param errorMessage The error message
     * @param errorCode Optional error code
     * @return Map representing the error response
     */
    private Map<String, Object> createErrorResponse(String errorMessage, int errorCode) {
        Map<String, Object> response = new HashMap<>();
        Map<String, Object> errorDetails = new HashMap<>();
        
        // Standard top-level structure
        response.put("status", "error");
        
        // Error details
        errorDetails.put("message", errorMessage);
        errorDetails.put("code", errorCode);
        
        response.put("error", errorDetails);
        
        return response;
    }
    
    /**
     * Creates a standardized success response
     * 
     * @param data The data to include in the response
     * @return Map representing the success response
     */
    private Map<String, Object> createSuccessResponse(Map<String, Object> data) {
        Map<String, Object> response = new HashMap<>();
        
        // Standard top-level structure
        response.put("status", "success");
        response.put("data", data);
        
        return response;
    }

    /**
     * Helper method to get a primitive data type from the program
     */
    private DataType getPrimitiveDataType(String dataTypeName) {
        DataTypeManager dtm = program.getDataTypeManager();

        // Handle common primitive types
        if ("byte".equalsIgnoreCase(dataTypeName)) {
            return dtm.getDataType("/byte");
        } else if ("word".equalsIgnoreCase(dataTypeName)) {
            return dtm.getDataType("/word");
        } else if ("dword".equalsIgnoreCase(dataTypeName)) {
            return dtm.getDataType("/dword");
        } else if ("qword".equalsIgnoreCase(dataTypeName)) {
            return dtm.getDataType("/qword");
        } else if ("float".equalsIgnoreCase(dataTypeName)) {
            return dtm.getDataType("/float");
        } else if ("double".equalsIgnoreCase(dataTypeName)) {
            return dtm.getDataType("/double");
        } else if ("char".equalsIgnoreCase(dataTypeName)) {
            return dtm.getDataType("/char");
        } else if ("undefined".equalsIgnoreCase(dataTypeName)) {
            return dtm.getDataType("/undefined");
        } else if ("void".equalsIgnoreCase(dataTypeName)) {
            return dtm.getDataType("/void");
        }

        // Try to find the data type directly (allows for more complex type names)
        return dtm.getDataType("/" + dataTypeName);
    }

    /**
     * Find a data type by name (searches in all categories)
     *
     * @param dataTypeName Name of the data type to find
     * @return The data type if found, null otherwise
     */
    public DataType findDataType(String dataTypeName) {
        DataTypeManager dtm = program.getDataTypeManager();

        // First try direct path lookup for exact match
        DataType dt = dtm.getDataType("/" + dataTypeName);
        if (dt != null) {
            return dt;
        }

        // Otherwise search through all data types
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType type = allTypes.next();
            if (type.getName().equals(dataTypeName)) {
                return type;
            }
        }

        return null;
    }

    /**
     * Create a new string data type at the specified address
     *
     * @param stringType Type of string to create ("string", "Unicode", "pascal")
     * @param addressStr Address where to create the string data type
     * @param length     Optional maximum length for the string (-1 for auto-detect)
     * @return Map containing the result of the operation
     */
    public Map<String, Object> createStringDataType(String stringType, String addressStr, int length) {
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return createErrorResponse("Invalid address: " + addressStr);
            }

            // Determine data type based on string type and length
            DataType dataType;

            if (length > 0) {
                // Create a character array for fixed length strings
                DataTypeManager dtm = program.getDataTypeManager();
                DataType charType;

                if ("string".equalsIgnoreCase(stringType) || "ascii".equalsIgnoreCase(stringType)) {
                    charType = dtm.getDataType("/char");
                } else if ("unicode".equalsIgnoreCase(stringType)) {
                    charType = dtm.getDataType("/wchar_t");
                } else if ("pascal".equalsIgnoreCase(stringType)) {
                    // Pascal strings can't easily be represented as fixed-length arrays
                    return createErrorResponse("Fixed-length not supported for Pascal strings");
                } else {
                    return createErrorResponse("Unsupported string type: " + stringType);
                }

                // Create array data type with the specified length
                dataType = new ArrayDataType(charType, length, charType.getLength());
            } else {
                // Use standard auto-terminated string types
                if ("string".equalsIgnoreCase(stringType) || "ascii".equalsIgnoreCase(stringType)) {
                    dataType = new StringDataType();
                } else if ("unicode".equalsIgnoreCase(stringType)) {
                    dataType = new UnicodeDataType();
                } else if ("pascal".equalsIgnoreCase(stringType)) {
                    dataType = new PascalStringDataType();
                } else {
                    return createErrorResponse("Unsupported string type: " + stringType);
                }
            }

            // Create the data
            Data data = program.getListing().createData(address, dataType);
            if (data == null) {
                return createErrorResponse("Failed to create string data at address " + addressStr);
            }

            // Create data for the success response
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("address", addressStr);
            responseData.put("stringType", stringType);
            responseData.put("dataType", dataType.getName());
            responseData.put("size", data.getLength());
            responseData.put("value", data.getDefaultValueRepresentation());

            if (length > 0) {
                responseData.put("fixedLength", length);
            }

            // Return standardized success response
            return createSuccessResponse(responseData);
        } catch (Exception e) {
            Msg.error(this, "Error creating string data type", e);
            return createErrorResponse("Error creating string data type: " + e.getMessage());
        }
    }

    /**
     * Create a new array data type at the specified address
     *
     * @param elementTypeName Name of the element data type
     * @param addressStr      Address where to create the array
     * @param numElements     Number of elements in the array
     * @return Map containing the result of the operation
     */
    public Map<String, Object> createArrayDataType(String elementTypeName, String addressStr, int numElements) {
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return createErrorResponse("Invalid address: " + addressStr);
            }

            if (numElements <= 0) {
                return createErrorResponse("Number of elements must be positive");
            }

            // Get the element data type
            DataType elementType = findDataType(elementTypeName);
            if (elementType == null) {
                return createErrorResponse("Unknown data type: " + elementTypeName);
            }

            // Create the array data type
            ArrayDataType arrayDataType = new ArrayDataType(elementType, numElements, elementType.getLength());

            // Create the data
            Data data = program.getListing().createData(address, arrayDataType);
            if (data == null) {
                return createErrorResponse("Failed to create array data at address " + addressStr);
            }

            // Create data for the success response
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("address", addressStr);
            responseData.put("elementType", elementTypeName);
            responseData.put("numElements", numElements);
            responseData.put("dataType", arrayDataType.getName());
            responseData.put("size", data.getLength());

            // Return standardized success response
            return createSuccessResponse(responseData);
        } catch (Exception e) {
            Msg.error(this, "Error creating array data type", e);
            return createErrorResponse("Error creating array data type: " + e.getMessage());
        }
    }

    /**
     * Create a new structure data type in the program's data type manager
     *
     * @param structureName Name of the structure to create
     * @param description   Optional description of the structure
     * @param packed        Whether the structure should be packed (no alignment)
     * @param alignment     Alignment value (e.g., 1, 2, 4, 8)
     * @return Map containing the result of the operation
     */
    public Map<String, Object> createStructureDataType(
            String structureName,
            String description,
            boolean packed,
            int alignment) {

        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        try {
            // Check if the structure already exists
            DataTypeManager dataTypeManager = program.getDataTypeManager();
            DataType existingType = findDataType(structureName);
            if (existingType != null) {
                return createErrorResponse("Structure already exists: " + structureName);
            }

            // Create the structure
            StructureDataType structureDataType = new StructureDataType(
                    CategoryPath.ROOT,
                    structureName,
                    0,
                    dataTypeManager);

            if (description != null && !description.isEmpty()) {
                structureDataType.setDescription(description);
            }

            if (packed) {
                structureDataType.setPackingEnabled(true);
            }

            if (alignment > 0) {
                structureDataType.setExplicitMinimumAlignment(alignment);
            }

            // Add the structure to the data type manager
            StructureDataType addedStructure = (StructureDataType) dataTypeManager.addDataType(
                    structureDataType,
                    DataTypeConflictHandler.DEFAULT_HANDLER);

            // Create success response
            return getStructureInfoMap(addedStructure);
        } catch (Exception e) {
            Msg.error(this, "Error creating structure data type", e);
            return createErrorResponse("Error creating structure: " + e.getMessage());
        }
    }

    private Map<String, Object> getStructureInfoMap(StructureDataType structure) {
        // Create data for the success response
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("name", structure.getName());
        responseData.put("id", structure.getUniversalID().getValue());
        responseData.put("category", structure.getCategoryPath().getPath());
        responseData.put("size", structure.getLength());
        responseData.put("alignment", structure.getAlignment());
        responseData.put("packed", structure.isPackingEnabled());

        if (structure.getDescription() != null) {
            responseData.put("description", structure.getDescription());
        }
        
        // Return standardized success response
        return createSuccessResponse(responseData);
    }

    /**
     * Add a field to an existing structure data type at the specified offset
     *
     * @param structureName Name of the structure to add the field to
     * @param fieldName     Name of the field to add
     * @param fieldTypeName Data type name for the field
     * @param comment       Optional comment for the field
     * @param offset        Byte offset where the field should be inserted (use structure.getLength() to append to the end)
     * @return Map containing the result of the operation
     */
    public Map<String, Object> addFieldToStructure(
            String structureName,
            String fieldName,
            String fieldTypeName,
            String comment,
            int offset) {

        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        try {
            // Find the structure
            DataType structureType = findDataType(structureName);
            if (structureType == null) {
                return createErrorResponse("Structure not found: " + structureName);
            }

            if (!(structureType instanceof Structure structure)) {
                return createErrorResponse("Data type is not a structure: " + structureName);
            }

            // Find the field data type
            DataType fieldType = findDataType(fieldTypeName);
            if (fieldType == null) {
                return createErrorResponse("Field data type not found: " + fieldTypeName);
            }

            // Add the field to the structure at the specified offset
            int length = fieldType.getLength();

            try {
                structure.insertAtOffset(offset, fieldType, length, fieldName, comment);
            } catch (IllegalArgumentException e) {
                // If insertion at the specified offset fails, check if we were trying to append
                if (offset == structure.getLength()) {
                    // This was an append operation, so grow the structure and try again
                    int currentLength = structure.getLength();
                    structure.growStructure(fieldType.getLength());

                    // Now insert at the newly available space at the end
                    structure.insertAtOffset(currentLength, fieldType, fieldType.getLength(), fieldName, comment);
                } else {
                    // For non-append operations, propagate the exception with more context
                    throw new IllegalArgumentException("Could not insert field '" + fieldName +
                            "' at offset " + offset + ": " + e.getMessage(), e);
                }
            }

            // Find the added component
            DataTypeComponent component = null;
            for (int i = 0; i < structure.getNumComponents(); i++) {
                DataTypeComponent comp = structure.getComponent(i);
                if (comp.getFieldName() != null && comp.getFieldName().equals(fieldName)) {
                    component = comp;
                    break;
                }
            }

            // Create data for the success response
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("structureName", structureName);
            responseData.put("fieldName", fieldName);
            responseData.put("fieldType", fieldTypeName);

            if (component != null) {
                responseData.put("offset", component.getOffset());
                responseData.put("length", component.getLength());
                responseData.put("ordinal", component.getOrdinal());

                if (component.getComment() != null) {
                    responseData.put("comment", component.getComment());
                }
            }

            responseData.put("structureSize", structure.getLength());

            // Return standardized success response
            return createSuccessResponse(responseData);
        } catch (Exception e) {
            Msg.error(this, "Error adding field to structure", e);
            return createErrorResponse("Error adding field to structure: " + e.getMessage());
        }
    }

    /**
     * Apply a structure data type to memory at a specified address
     *
     * @param structureName Name of the structure to apply
     * @param addressStr    Address where to apply the structure
     * @return Map containing the result of the operation
     */
    public Map<String, Object> applyStructureToMemory(
            String structureName,
            String addressStr) {

        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return createErrorResponse("Invalid address: " + addressStr);
            }

            // Find the structure
            DataType structureType = findDataType(structureName);
            if (structureType == null) {
                return createErrorResponse("Structure not found: " + structureName);
            }

            if (!(structureType instanceof Structure)) {
                return createErrorResponse("Data type is not a structure: " + structureName);
            }

            // Apply the structure to memory
            Data data = program.getListing().createData(address, structureType);
            if (data == null) {
                return createErrorResponse("Failed to apply structure at address " + addressStr);
            }

            // Create data for the success response
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("address", addressStr);
            responseData.put("structureName", structureName);
            responseData.put("size", data.getLength());

            // Get field information
            List<Map<String, Object>> fields = new ArrayList<>();
            for (int i = 0; i < data.getNumComponents(); i++) {
                Data component = data.getComponent(i);
                if (component != null) {
                    Map<String, Object> field = new HashMap<>();
                    field.put("name", component.getFieldName());
                    field.put("offset", component.getParentOffset());
                    field.put("dataType", component.getDataType().getName());
                    field.put("address", component.getAddress().toString());
                    field.put("value", component.getDefaultValueRepresentation());
                    fields.add(field);
                }
            }

            responseData.put("fields", fields);
            
            // Return standardized success response
            return createSuccessResponse(responseData);
        } catch (Exception e) {
            Msg.error(this, "Error applying structure to memory", e);
            return createErrorResponse("Error applying structure: " + e.getMessage());
        }
    }

    /**
     * Delete a data type from the program's data type manager
     *
     * @param dataTypeName Name of the data type to delete
     * @return Map containing the result of the operation
     */
    public Map<String, Object> deleteDataType(String dataTypeName) {
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        try {
            // Find the data type
            DataType dataType = findDataType(dataTypeName);
            if (dataType == null) {
                return createErrorResponse("Data type not found: " + dataTypeName);
            }

            // Check if it's a built-in type
            if (dataType.getSourceArchive().getArchiveType() == ArchiveType.BUILT_IN) {
                return createErrorResponse("Cannot delete built-in data type: " + dataTypeName);
            }

            // Delete the data type
            boolean deleted = program.getDataTypeManager().remove(dataType, TaskMonitor.DUMMY);

            if (!deleted) {
                // Return error response if deletion failed
                return createErrorResponse("Failed to delete data type: " + dataTypeName + ". It may be in use or protected.");
            }
            
            // Create data for the success response
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("dataTypeName", dataTypeName);
            responseData.put("deleted", true);
            
            // Return standardized success response
            return createSuccessResponse(responseData);
        } catch (Exception e) {
            Msg.error(this, "Error deleting data type", e);
            return createErrorResponse("Error deleting data type: " + e.getMessage());
        }
    }

    /**
     * List all data types matching a search pattern
     *
     * @param searchPattern Pattern to search for (null or empty to list all)
     * @param categoryPath  Optional category path to filter by
     * @param offset        Starting position for pagination
     * @param limit         Maximum number of results to return
     * @return Map containing the search results
     */
    public Map<String, Object> searchDataTypes(
            String searchPattern,
            String categoryPath,
            int offset,
            int limit) {

        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        try {
            DataTypeManager dataTypeManager = program.getDataTypeManager();
            List<DataType> matchingDataTypes = new ArrayList<>();

            // Convert pattern to lowercase for case-insensitive search
            String pattern = searchPattern == null ? "" : searchPattern.toLowerCase();

            // Parse the category path if provided
            CategoryPath categoryPathObj = null;
            if (categoryPath != null && !categoryPath.isEmpty()) {
                categoryPathObj = new CategoryPath(categoryPath);
            }

            // Collect matching data types
            Iterator<DataType> dtIterator = dataTypeManager.getAllDataTypes();
            while (dtIterator.hasNext()) {
                DataType dt = dtIterator.next();

                // Skip if it doesn't match the category
                if (categoryPathObj != null && !dt.getCategoryPath().isAncestorOrSelf(categoryPathObj)) {
                    continue;
                }

                // Always include if no pattern, otherwise check if name contains pattern
                if (pattern.isEmpty() || dt.getName().toLowerCase().contains(pattern)) {
                    matchingDataTypes.add(dt);
                }
            }

            // Sort by name for consistent ordering
            matchingDataTypes.sort(Comparator.comparing(DataType::getName));

            // Apply pagination
            int start = Math.max(0, offset);
            int end = Math.min(matchingDataTypes.size(), offset + limit);
            List<DataType> pagedDataTypes = start >= matchingDataTypes.size() ?
                    new ArrayList<>() :
                    matchingDataTypes.subList(start, end);

            // Convert to result format
            List<Map<String, Object>> results = new ArrayList<>();
            for (DataType dt : pagedDataTypes) {
                Map<String, Object> dataTypeInfo = getDataTypeInfoMap(dt);
                results.add(dataTypeInfo);
            }

            // Create data for the success response
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("dataTypes", results);
            responseData.put("total", matchingDataTypes.size());
            responseData.put("offset", offset);
            responseData.put("limit", limit);

            if (searchPattern != null && !searchPattern.isEmpty()) {
                responseData.put("searchPattern", searchPattern);
            }

            if (categoryPath != null && !categoryPath.isEmpty()) {
                responseData.put("categoryPath", categoryPath);
            }
            
            // Return standardized success response
            return createSuccessResponse(responseData);
        } catch (Exception e) {
            Msg.error(this, "Error searching data types", e);
            return createErrorResponse("Error searching data types: " + e.getMessage());
        }
    }

    private Map<String, Object> getDataTypeInfoMap(DataType dt) {
        Map<String, Object> dataTypeInfo = new HashMap<>();
        dataTypeInfo.put("name", dt.getName());
        dataTypeInfo.put("category", dt.getCategoryPath().getPath());
        dataTypeInfo.put("size", dt.getLength());
        dataTypeInfo.put("id", dt.getUniversalID().getValue());
        dataTypeInfo.put("isBuiltIn", dt.getSourceArchive().getArchiveType() == ArchiveType.BUILT_IN);

        if (dt.getDescription() != null && !dt.getDescription().isEmpty()) {
            dataTypeInfo.put("description", dt.getDescription());
        }

        // Add structure-specific information
        if (dt instanceof Structure struct) {
            dataTypeInfo.put("isStructure", true);
            dataTypeInfo.put("alignment", struct.getAlignment());
            dataTypeInfo.put("packed", struct.isPackingEnabled());
            dataTypeInfo.put("componentCount", struct.getNumComponents());

            // Include field information for small structures
            if (struct.getNumComponents() <= 20) {
                List<Map<String, Object>> fields = new ArrayList<>();
                for (int i = 0; i < struct.getNumComponents(); i++) {
                    DataTypeComponent component = struct.getComponent(i);
                    Map<String, Object> field = new HashMap<>();
                    field.put("name", component.getFieldName());
                    field.put("offset", component.getOffset());
                    field.put("dataType", component.getDataType().getName());
                    field.put("length", component.getLength());

                    if (component.getComment() != null) {
                        field.put("comment", component.getComment());
                    }

                    fields.add(field);
                }
                dataTypeInfo.put("fields", fields);
            }
        }

        // Add enum-specific information
        if (dt instanceof Enum enumType) {
            dataTypeInfo.put("isEnum", true);
            dataTypeInfo.put("valueCount", enumType.getCount());

            // Include enum values for small enums
            if (enumType.getCount() <= 20) {
                Map<String, Long> values = new HashMap<>();
                for (String name : enumType.getNames()) {
                    values.put(name, enumType.getValue(name));
                }
                dataTypeInfo.put("values", values);
            }
        }
        return dataTypeInfo;
    }

    /**
     * Create a new enumeration data type in the program's data type manager
     *
     * @param enumName    Name of the enum to create
     * @param valueSize   Size of the enum values in bytes (1, 2, 4, or 8)
     * @param values      Map of name to value pairs for enum entries
     * @param description Optional description of the enum
     * @return Map containing the result of the operation
     */
    public Map<String, Object> createEnumDataType(
            String enumName,
            int valueSize,
            Map<String, Long> values,
            String description) {

        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        try {
            // Validate valueSize
            if (valueSize != 1 && valueSize != 2 && valueSize != 4 && valueSize != 8) {
                return createErrorResponse("Invalid enum value size. Must be 1, 2, 4, or 8 bytes.");
            }

            // Check if the enum already exists
            DataTypeManager dataTypeManager = program.getDataTypeManager();
            DataType existingType = findDataType(enumName);
            if (existingType != null) {
                return createErrorResponse("Enum already exists: " + enumName);
            }

            // Create the enum
            EnumDataType enumDataType = new EnumDataType(CategoryPath.ROOT, enumName, valueSize, dataTypeManager);

            if (description != null && !description.isEmpty()) {
                enumDataType.setDescription(description);
            }

            // Add values to the enum
            if (values != null) {
                for (Map.Entry<String, Long> entry : values.entrySet()) {
                    enumDataType.add(entry.getKey(), entry.getValue());
                }
            }

            // Add the enum to the data type manager
            EnumDataType addedEnum = (EnumDataType) dataTypeManager.addDataType(
                    enumDataType,
                    DataTypeConflictHandler.DEFAULT_HANDLER);

            // Create data for the success response
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("name", addedEnum.getName());
            responseData.put("id", addedEnum.getUniversalID().getValue());
            responseData.put("category", addedEnum.getCategoryPath().getPath());
            responseData.put("valueSize", addedEnum.getLength());
            responseData.put("valueCount", addedEnum.getCount());

            if (addedEnum.getDescription() != null) {
                responseData.put("description", addedEnum.getDescription());
            }

            // Include enum values
            Map<String, Long> enumValues = new HashMap<>();
            for (String name : addedEnum.getNames()) {
                enumValues.put(name, addedEnum.getValue(name));
            }
            responseData.put("values", enumValues);

            // Return standardized success response
            return createSuccessResponse(responseData);
        } catch (Exception e) {
            Msg.error(this, "Error creating enum data type", e);
            return createErrorResponse("Error creating enum: " + e.getMessage());
        }
    }

    /**
     * Apply an enum data type to memory at a specified address
     *
     * @param enumName   Name of the enum to apply
     * @param addressStr Address where to apply the enum
     * @return Map containing the result of the operation
     */
    public Map<String, Object> applyEnumToMemory(
            String enumName,
            String addressStr) {

        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return createErrorResponse("Invalid address: " + addressStr);
            }

            // Find the enum
            DataType enumType = findDataType(enumName);
            if (enumType == null) {
                return createErrorResponse("Enum not found: " + enumName);
            }

            if (!(enumType instanceof Enum enumDt)) {
                return createErrorResponse("Data type is not an enum: " + enumName);
            }

            // Apply the enum to memory
            Data data = program.getListing().createData(address, enumType);
            if (data == null) {
                return createErrorResponse("Failed to apply enum at address " + addressStr);
            }

            // Get the current value
            long value = data.getScalar(0).getUnsignedValue();
            String valueName = null;

            // Try to find the name for this value
            for (String name : enumDt.getNames()) {
                if (enumDt.getValue(name) == value) {
                    valueName = name;
                    break;
                }
            }

            // Create data for the success response
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("address", addressStr);
            responseData.put("enumName", enumName);
            responseData.put("value", value);

            if (valueName != null) {
                responseData.put("valueName", valueName);
            }

            // Return standardized success response
            return createSuccessResponse(responseData);
        } catch (Exception e) {
            Msg.error(this, "Error applying enum to memory", e);
            return createErrorResponse("Error applying enum: " + e.getMessage());
        }
    }

    /**
     * Get a data type category and its contents
     *
     * @param categoryPath Path of the category to get
     * @return Map containing the category information
     */
    public Map<String, Object> getDataTypeCategory(String categoryPath) {
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        try {
            DataTypeManager dataTypeManager = program.getDataTypeManager();

            // Use ROOT if no category path is provided
            CategoryPath path = categoryPath == null || categoryPath.isEmpty() ?
                    CategoryPath.ROOT : new CategoryPath(categoryPath);

            // Get the category
            Category category = dataTypeManager.getCategory(path);
            if (category == null) {
                return createErrorResponse("Category not found: " + path.getPath());
            }

            // Get subcategories
            List<Map<String, Object>> subcategories = getCategoryInfoList(category);

            // Get data types in this category
            List<Map<String, Object>> dataTypes = new ArrayList<>();
            for (DataType dt : category.getDataTypes()) {
                Map<String, Object> dataTypeInfo = getCategoryDataTypeInfoMap(dt);
                dataTypes.add(dataTypeInfo);
            }

            // Create data for the success response
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("categoryPath", category.getCategoryPath().getPath());
            responseData.put("name", category.getName());
            responseData.put("subcategories", subcategories);
            responseData.put("dataTypes", dataTypes);
            responseData.put("subcategoryCount", subcategories.size());
            responseData.put("dataTypeCount", dataTypes.size());

            // Return standardized success response
            return createSuccessResponse(responseData);
        } catch (Exception e) {
            Msg.error(this, "Error getting data type category", e);
            return createErrorResponse("Error getting data type category: " + e.getMessage());
        }
    }

    private List<Map<String, Object>> getCategoryInfoList(Category category) {
        List<Map<String, Object>> subcategories = new ArrayList<>();
        for (Category subcat : category.getCategories()) {
            Map<String, Object> subcatInfo = new HashMap<>();
            subcatInfo.put("name", subcat.getName());
            subcatInfo.put("path", subcat.getCategoryPath().getPath());
            subcatInfo.put("categoryCount", subcat.getCategories().length);
            subcatInfo.put("dataTypeCount", subcat.getDataTypes().length);
            subcategories.add(subcatInfo);
        }
        return subcategories;
    }

    private Map<String, Object> getCategoryDataTypeInfoMap(DataType dt) {
        Map<String, Object> dataTypeInfo = new HashMap<>();
        dataTypeInfo.put("name", dt.getName());
        dataTypeInfo.put("size", dt.getLength());
        dataTypeInfo.put("id", dt.getUniversalID().getValue());
        dataTypeInfo.put("isBuiltIn", dt.getSourceArchive().getArchiveType() == ArchiveType.BUILT_IN);

        if (dt instanceof Structure) {
            dataTypeInfo.put("type", "Structure");
        } else if (dt instanceof Union) {
            dataTypeInfo.put("type", "Union");
        } else if (dt instanceof Enum) {
            dataTypeInfo.put("type", "Enum");
        } else if (dt instanceof TypeDef) {
            dataTypeInfo.put("type", "TypeDef");
        } else if (dt instanceof Array) {
            dataTypeInfo.put("type", "Array");
        } else {
            dataTypeInfo.put("type", "Primitive");
        }
        return dataTypeInfo;
    }
}
