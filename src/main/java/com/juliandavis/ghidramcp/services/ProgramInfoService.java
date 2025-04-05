package com.juliandavis.ghidramcp.services;

import com.juliandavis.ghidramcp.core.service.Service;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Service for accessing program metadata, functions, symbols, and other information.
 * <p>
 * This service provides methods for retrieving various types of program information,
 * including program metadata, functions, namespaces, segments, imports, exports, and more.
 */
public class ProgramInfoService implements Service {

    public static final String SERVICE_NAME = "ProgramInfoService";
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
     * Get detailed metadata about the currently loaded program.
     *
     * @param includeDetailedStats Whether to include detailed statistics (which can be expensive to compute)
     * @return Map containing program metadata
     */
    public Map<String, Object> getProgramMetadata(boolean includeDetailedStats) {
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        // Create metadata with appropriate level of detail
        Map<String, Object> metadata = new HashMap<>();

        // Basic program information (always include)
        addBasicProgramInfo(program, metadata);

        // Add detailed stats if requested
        if (includeDetailedStats) {
            addDetailedProgramStats(program, metadata);
        }

        return createSuccessResponse(metadata);
    }
    
    /**
     * Add basic program information (fast to compute)
     */
    private void addBasicProgramInfo(Program program, Map<String, Object> metadata) {
        // Basic program information
        metadata.put("name", program.getName());
        metadata.put("location", program.getExecutablePath());
        metadata.put("creationDate", program.getCreationDate().toString());
        metadata.put("languageID", program.getLanguageID().toString());
        metadata.put("compilerSpec", program.getCompilerSpec().getCompilerSpecID().toString());
        metadata.put("imageBase", program.getImageBase().toString());
        metadata.put("executableFormat", program.getExecutableFormat());
        metadata.put("addressSize", program.getAddressFactory().getDefaultAddressSpace().getSize());

        // Quick memory statistics
        Map<String, Object> memoryStats = new HashMap<>();
        long totalBytes = 0;
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            totalBytes += block.getSize();
        }
        memoryStats.put("totalSize", totalBytes);
        memoryStats.put("blockCount", program.getMemory().getBlocks().length);
        metadata.put("memory", memoryStats);

        // Simple function count
        Map<String, Object> functionStats = new HashMap<>();
        functionStats.put("totalCount", program.getFunctionManager().getFunctionCount());
        metadata.put("functions", functionStats);

        // Simple symbol count
        Map<String, Object> symbolStats = new HashMap<>();
        symbolStats.put("totalCount", program.getSymbolTable().getNumSymbols());
        metadata.put("symbols", symbolStats);

        // Processor architecture info (fast to compute)
        Map<String, Object> processorInfo = new HashMap<>();
        processorInfo.put("name", program.getLanguage().getProcessor().toString());
        processorInfo.put("endian", program.getLanguage().isBigEndian() ? "big" : "little");
        processorInfo.put("wordSize", program.getLanguage().getLanguageDescription().getSize());
        metadata.put("processor", processorInfo);
    }
    
    /**
     * Add detailed program statistics (potentially slow for large programs)
     */
    private void addDetailedProgramStats(Program program, Map<String, Object> metadata) {
        // Enhance function statistics with external/internal counts
        Map<String, Object> functionStats = (Map<String, Object>) metadata.get("functions");
        int externalCount = 0;
        int internalCount = 0;

        // Count external vs internal functions (limited to 5000 to avoid performance issues)
        Iterator<Function> funcIt = program.getFunctionManager().getFunctions(true);
        int count = 0;
        while (funcIt.hasNext() && count < 5000) {
            Function func = funcIt.next();
            if (func.isExternal()) {
                externalCount++;
            } else {
                internalCount++;
            }
            count++;
        }

        // Update function stats if we processed all functions
        if (count == program.getFunctionManager().getFunctionCount()) {
            functionStats.put("externalCount", externalCount);
            functionStats.put("internalCount", internalCount);
        } else {
            functionStats.put("note", "Partial count, use /programInfo/functionStats for complete statistics");
        }

        // Add placeholder for data types
        Map<String, Object> dataTypeStats = new HashMap<>();
        dataTypeStats.put("note", "For detailed data type statistics, use the /programInfo/dataTypeStats endpoint");
        metadata.put("dataTypes", dataTypeStats);
    }
    
    /**
     * Get all function names with pagination.
     *
     * @param offset Starting position for pagination
     * @param limit  Maximum number of items to return
     * @return Map of function data
     */
    public Map<String, Object> getAllFunctionNames(int offset, int limit) {
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        List<Map<String, Object>> functions = new ArrayList<>();
        List<Function> allFunctions = new ArrayList<>();

        // Collect all functions first
        program.getFunctionManager().getFunctions(true).forEach(allFunctions::add);

        // Sort by name for consistent ordering
        allFunctions.sort(Comparator.comparing(Function::getName));

        // Apply pagination
        int start = Math.max(0, offset);
        int end = Math.min(allFunctions.size(), offset + limit);
        List<Function> pagedFunctions = start >= allFunctions.size() ?
                new ArrayList<>() :
                allFunctions.subList(start, end);

        // Create rich function objects with more data
        for (Function f : pagedFunctions) {
            Map<String, Object> functionData = new HashMap<>();
            functionData.put("name", f.getName());
            functionData.put("address", f.getEntryPoint().toString());
            functionData.put("signature", f.getSignature().toString());
            functionData.put("returnType", f.getReturnType().toString());
            functionData.put("parameterCount", f.getParameterCount());
            functions.add(functionData);
        }

        // Create paginated response
        Map<String, Object> result = new HashMap<>();
        result.put("functions", functions);
        result.put("count", functions.size());
        result.put("offset", offset);
        result.put("limit", limit);
        result.put("total", allFunctions.size());

        return createSuccessResponse(result);
    }
    
    /**
     * Get function statistics with time-bounded processing and continuation support.
     *
     * @param continuationToken Token from a previous request to resume processing
     * @param limit             Maximum number of functions to process in this request
     * @return Response with function statistics and continuation info
     */
    public Map<String, Object> getFunctionStats(String continuationToken, int limit) {
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        Map<String, Object> stats = new HashMap<>();

        // Always include total count (fast operation)
        stats.put("totalCount", program.getFunctionManager().getFunctionCount());

        // Parse continuation token
        int externalProcessed = 0;
        int internalProcessed = 0;

        if (continuationToken != null && !continuationToken.isEmpty()) {
            String[] parts = continuationToken.split(":");
            if (parts.length == 2) {
                try {
                    externalProcessed = Integer.parseInt(parts[0]);
                    internalProcessed = Integer.parseInt(parts[1]);
                } catch (NumberFormatException e) {
                    Msg.warn(this, "Invalid continuation token: " + continuationToken);
                }
            }
        }

        // Count functions within time constraints
        int externalCount = externalProcessed;
        int internalCount = internalProcessed;
        int processedCount = 0;

        Iterator<Function> it = program.getFunctionManager().getFunctions(true);
        long startTime = System.currentTimeMillis();
        final long MAX_PROCESSING_TIME = 25000; // 25 seconds, giving 5 seconds buffer

        // Skip already processed functions
        int totalToSkip = externalProcessed + internalProcessed;
        int skipped = 0;
        while (it.hasNext() && skipped < totalToSkip) {
            it.next();
            skipped++;
        }

        // Process functions up to the limit or time constraint
        while (it.hasNext() && processedCount < limit) {
            // Check time constraints
            if (System.currentTimeMillis() - startTime > MAX_PROCESSING_TIME) {
                break;
            }

            Function func = it.next();
            if (func.isExternal()) {
                externalCount++;
            } else {
                internalCount++;
            }

            processedCount++;
        }

        // Determine if processing is complete
        boolean isComplete = !it.hasNext();

        // Add stats to response
        stats.put("externalCount", externalCount);
        stats.put("internalCount", internalCount);
        stats.put("processedCount", externalProcessed + internalProcessed + processedCount);

        // Build response
        Map<String, Object> response = new HashMap<>();
        response.put("stats", stats);
        response.put("isComplete", isComplete);
        if (!isComplete) {
            response.put("continuationToken", externalCount + ":" + internalCount);
        }

        return createSuccessResponse(response);
    }
    
    /**
     * List memory segments with pagination.
     *
     * @param offset Starting position for pagination
     * @param limit  Maximum number of items to return
     * @return Map of segment data
     */
    public Map<String, Object> listSegments(int offset, int limit) {
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        List<Map<String, Object>> segments = new ArrayList<>();

        // Collect all memory blocks
        List<MemoryBlock> blocks = new ArrayList<>(Arrays.asList(program.getMemory().getBlocks()));

        // Apply pagination
        int start = Math.max(0, offset);
        int end = Math.min(blocks.size(), offset + limit);
        List<MemoryBlock> pagedBlocks = start >= blocks.size() ?
                new ArrayList<>() :
                blocks.subList(start, end);

        // Create rich segment objects with more data
        for (MemoryBlock block : pagedBlocks) {
            Map<String, Object> segmentData = new HashMap<>();
            segmentData.put("name", block.getName());
            segmentData.put("start", block.getStart().toString());
            segmentData.put("end", block.getEnd().toString());
            segmentData.put("size", block.getSize());
            segmentData.put("readable", block.isRead());
            segmentData.put("writable", block.isWrite());
            segmentData.put("executable", block.isExecute());
            segments.add(segmentData);
        }

        // Create paginated response
        Map<String, Object> result = new HashMap<>();
        result.put("segments", segments);
        result.put("count", segments.size());
        result.put("offset", offset);
        result.put("limit", limit);
        result.put("total", blocks.size());

        return createSuccessResponse(result);
    }
    
    /**
     * List imported symbols with pagination.
     *
     * @param offset Starting position for pagination
     * @param limit  Maximum number of items to return
     * @return Map of import data
     */
    public Map<String, Object> listImports(int offset, int limit) {
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        List<Map<String, Object>> imports = new ArrayList<>();
        List<Symbol> externalSymbols = new ArrayList<>();

        // Collect all external symbols
        program.getSymbolTable().getExternalSymbols().forEach(externalSymbols::add);

        // Apply pagination
        int start = Math.max(0, offset);
        int end = Math.min(externalSymbols.size(), offset + limit);
        List<Symbol> pagedSymbols = start >= externalSymbols.size() ?
                new ArrayList<>() :
                externalSymbols.subList(start, end);

        // Create rich import objects with more data
        for (Symbol symbol : pagedSymbols) {
            Map<String, Object> importData = new HashMap<>();
            importData.put("name", symbol.getName());
            importData.put("address", symbol.getAddress().toString());
            importData.put("namespace", symbol.getParentNamespace().getName());
            importData.put("symbolType", symbol.getSymbolType().toString());
            imports.add(importData);
        }

        // Create paginated response
        Map<String, Object> result = new HashMap<>();
        result.put("imports", imports);
        result.put("count", imports.size());
        result.put("offset", offset);
        result.put("limit", limit);
        result.put("total", externalSymbols.size());

        return createSuccessResponse(result);
    }
    
    /**
     * List exported functions/symbols with pagination.
     *
     * @param offset Starting position for pagination
     * @param limit  Maximum number of items to return
     * @return Map of export data
     */
    public Map<String, Object> listExports(int offset, int limit) {
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        List<Map<String, Object>> exports = new ArrayList<>();
        List<Symbol> exportSymbols = new ArrayList<>();

        // Collect all export symbols
        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);
        while (it.hasNext()) {
            Symbol s = it.next();
            // On older Ghidra, "export" is recognized via isExternalEntryPoint()
            if (s.isExternalEntryPoint()) {
                exportSymbols.add(s);
            }
        }

        // Apply pagination
        int start = Math.max(0, offset);
        int end = Math.min(exportSymbols.size(), offset + limit);
        List<Symbol> pagedSymbols = start >= exportSymbols.size() ?
                new ArrayList<>() :
                exportSymbols.subList(start, end);

        // Create rich export objects with more data
        for (Symbol symbol : pagedSymbols) {
            Map<String, Object> exportData = new HashMap<>();
            exportData.put("name", symbol.getName());
            exportData.put("address", symbol.getAddress().toString());
            exportData.put("namespace", symbol.getParentNamespace().getName());
            exportData.put("symbolType", symbol.getSymbolType().toString());
            exports.add(exportData);
        }

        // Create paginated response
        Map<String, Object> result = new HashMap<>();
        result.put("exports", exports);
        result.put("count", exports.size());
        result.put("offset", offset);
        result.put("limit", limit);
        result.put("total", exportSymbols.size());

        return createSuccessResponse(result);
    }
    
    /**
     * List all non-global namespaces with pagination.
     *
     * @param offset Starting position for pagination
     * @param limit  Maximum number of items to return
     * @return Map of namespace data
     */
    public Map<String, Object> listNamespaces(int offset, int limit) {
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        Set<Namespace> namespaceSet = new HashSet<>();

        // Collect all namespaces
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                namespaceSet.add(ns);
            }
        }

        // Convert to list and sort for consistent ordering
        List<Namespace> sortedNamespaces = new ArrayList<>(namespaceSet);
        sortedNamespaces.sort(Comparator.comparing(Namespace::getName));

        // Apply pagination
        int start = Math.max(0, offset);
        int end = Math.min(sortedNamespaces.size(), offset + limit);
        List<Namespace> pagedNamespaces = start >= sortedNamespaces.size() ?
                new ArrayList<>() :
                sortedNamespaces.subList(start, end);

        // Create rich namespace objects with more data
        List<Map<String, Object>> namespaces = new ArrayList<>();
        for (Namespace ns : pagedNamespaces) {
            Map<String, Object> namespaceData = new HashMap<>();
            namespaceData.put("name", ns.getName());
            namespaceData.put("id", ns.getID());
            namespaceData.put("parentNamespace", ns.getParentNamespace().getName());
            namespaces.add(namespaceData);
        }

        // Create paginated response
        Map<String, Object> result = new HashMap<>();
        result.put("namespaces", namespaces);
        result.put("count", namespaces.size());
        result.put("offset", offset);
        result.put("limit", limit);
        result.put("total", sortedNamespaces.size());

        return createSuccessResponse(result);
    }

    /**
     * Escape non-ASCII chars to avoid potential decode issues.
     */
    private String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            }
            else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Get all class names with pagination.
     *
     * @param offset Starting position for pagination
     * @param limit  Maximum number of items to return
     * @return Map of class data
     */
    public Map<String, Object> getAllClassNames(int offset, int limit) {
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        Set<String> classNamesSet = new HashSet<>();
        Map<String, Namespace> classMap = new HashMap<>();

        // Collect all classes
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNamesSet.add(ns.getName());
                classMap.put(ns.getName(), ns);
            }
        }

        // Convert to list and sort for consistent ordering
        List<String> sortedNames = new ArrayList<>(classNamesSet);
        Collections.sort(sortedNames);

        // Apply pagination
        int start = Math.max(0, offset);
        int end = Math.min(sortedNames.size(), offset + limit);
        List<String> pagedNames = start >= sortedNames.size() ?
                new ArrayList<>() :
                sortedNames.subList(start, end);

        // Create rich class objects with more data
        List<Map<String, Object>> classes = new ArrayList<>();
        for (String className : pagedNames) {
            Map<String, Object> classData = new HashMap<>();
            Namespace ns = classMap.get(className);
            classData.put("name", className);
            classData.put("id", ns.getID());
            classData.put("parentNamespace", ns.getParentNamespace().getName());
            classes.add(classData);
        }

        // Create paginated response
        Map<String, Object> result = new HashMap<>();
        result.put("classes", classes);
        result.put("count", classes.size());
        result.put("offset", offset);
        result.put("limit", limit);
        result.put("total", sortedNames.size());

        return createSuccessResponse(result);
    }
    
    /**
     * List defined data labels and their values with pagination.
     *
     * @param offset Starting position for pagination
     * @param limit  Maximum number of items to return
     * @return Map of data items
     */
    public Map<String, Object> listDefinedData(int offset, int limit) {
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        List<Data> allData = new ArrayList<>();

        // Collect all defined data
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    allData.add(data);
                }
            }
        }

        // Apply pagination
        int start = Math.max(0, offset);
        int end = Math.min(allData.size(), offset + limit);
        List<Data> pagedData = start >= allData.size() ?
                new ArrayList<>() :
                allData.subList(start, end);

        // Create rich data objects with more data
        List<Map<String, Object>> dataItems = new ArrayList<>();
        for (Data data : pagedData) {
            Map<String, Object> dataItem = new HashMap<>();
            String label = data.getLabel() != null ? data.getLabel() : "(unnamed)";
            String valRepr = data.getDefaultValueRepresentation();

            dataItem.put("address", data.getAddress().toString());
            dataItem.put("label", escapeNonAscii(label));
            dataItem.put("value", escapeNonAscii(valRepr));
            dataItem.put("dataType", data.getDataType().getName());
            dataItem.put("dataLength", data.getLength());

            dataItems.add(dataItem);
        }

        // Create paginated response
        Map<String, Object> result = new HashMap<>();
        result.put("items", dataItems);
        result.put("count", dataItems.size());
        result.put("offset", offset);
        result.put("limit", limit);
        result.put("total", allData.size());

        return createSuccessResponse(result);
    }
    
    /**
     * Search for functions whose name contains the given substring.
     *
     * @param searchTerm The search term to look for in function names
     * @param offset     Starting position for pagination
     * @param limit      Maximum number of items to return
     * @return Map of matching functions
     */
    public Map<String, Object> searchFunctionsByName(String searchTerm, int offset, int limit) {
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        if (searchTerm == null || searchTerm.isEmpty()) {
            return createErrorResponse("Search term is required");
        }

        List<Function> matchingFunctions = new ArrayList<>();

        // Collect all matching functions
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            // simple substring match
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matchingFunctions.add(func);
            }
        }

        // Sort for consistent ordering
        matchingFunctions.sort(Comparator.comparing(Function::getName));

        // Apply pagination
        int start = Math.max(0, offset);
        int end = Math.min(matchingFunctions.size(), offset + limit);
        List<Function> pagedFunctions = start >= matchingFunctions.size() ?
                new ArrayList<>() :
                matchingFunctions.subList(start, end);

        // Create rich function objects with more data
        List<Map<String, Object>> functions = new ArrayList<>();
        for (Function func : pagedFunctions) {
            Map<String, Object> functionData = new HashMap<>();
            functionData.put("name", func.getName());
            functionData.put("address", func.getEntryPoint().toString());
            functionData.put("signature", func.getSignature().toString());
            functionData.put("returnType", func.getReturnType().toString());
            functionData.put("parameterCount", func.getParameterCount());
            functions.add(functionData);
        }

        // Create paginated response
        Map<String, Object> result = new HashMap<>();
        result.put("functions", functions);
        result.put("count", functions.size());
        result.put("offset", offset);
        result.put("limit", limit);
        result.put("total", matchingFunctions.size());
        result.put("searchTerm", searchTerm);

        return createSuccessResponse(result);
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
     * Get symbol statistics with time-bounded processing and continuation support.
     *
     * @param continuationToken Token from a previous request to resume processing
     * @param limit Maximum number of symbols to process in this request
     * @param symbolType Optional filter for a specific symbol type
     * @return Response with symbol statistics and continuation info
     */
    public Map<String, Object> getSymbolStats(String continuationToken, int limit, String symbolType) {
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        SymbolTable symbolTable = program.getSymbolTable();
        Map<String, Object> stats = new HashMap<>();
        List<Map<String, Object>> items = new ArrayList<>();

        // Always include total count (fast operation)
        stats.put("totalCount", symbolTable.getNumSymbols());

        // Parse continuation token to get starting position
        int startPosition = 0;
        if (continuationToken != null && !continuationToken.isEmpty()) {
            try {
                startPosition = Integer.parseInt(continuationToken);
            } catch (NumberFormatException e) {
                Msg.warn(this, "Invalid continuation token: " + continuationToken);
            }
        }

        // Track counts per type
        Map<String, Integer> typeCountMap = new HashMap<>();

        // Get symbol iterator
        SymbolIterator it = symbolTable.getAllSymbols(true);

        // Skip to starting position
        int currentPosition = 0;
        while (it.hasNext() && currentPosition < startPosition) {
            it.next();
            currentPosition++;
        }

        // Process symbols with time and count limits
        int processed = 0;
        long startTime = System.currentTimeMillis();
        final long MAX_PROCESSING_TIME = 25000; // 25 seconds

        while (it.hasNext() && processed < limit) {
            // Check time constraint
            if (System.currentTimeMillis() - startTime > MAX_PROCESSING_TIME) {
                break;
            }

            Symbol symbol = it.next();
            currentPosition++;

            // Update type count
            String typeName = symbol.getSymbolType().toString();
            typeCountMap.put(typeName, typeCountMap.getOrDefault(typeName, 0) + 1);

            // If filtering by type, only add matching symbols to the items list
            if (symbolType == null || symbolType.equalsIgnoreCase(typeName)) {
                if (items.size() < 100) { // Limit detailed items to first 100 matching
                    Map<String, Object> symbolData = new HashMap<>();
                    symbolData.put("name", symbol.getName());
                    symbolData.put("address", symbol.getAddress().toString());
                    symbolData.put("type", typeName);
                    symbolData.put("namespace", symbol.getParentNamespace().getName());
                    items.add(symbolData);
                }
            }

            processed++;
        }

        // Determine if there's more data
        boolean isComplete = !it.hasNext();

        // Add all type counts to stats
        for (Map.Entry<String, Integer> entry : typeCountMap.entrySet()) {
            stats.put(entry.getKey() + "Count", entry.getValue());
        }

        Map<String, Object> response = new HashMap<>();
        response.put("symbolStats", stats);
        response.put("items", !items.isEmpty() ? items : Collections.emptyList());
        response.put("processedCount", processed);
        response.put("isComplete", isComplete);
        response.put("continuationToken", isComplete ? "" : String.valueOf(currentPosition));

        return createSuccessResponse(response);
    }

    /**
     * Get data type statistics with time-bounded processing and continuation support.
     *
     * @param continuationToken Token from a previous request to resume processing
     * @param limit Maximum number of data types to process in this request
     * @return Response with data type statistics and continuation info
     */
    public Map<String, Object> getDataTypeStats(String continuationToken, int limit) {
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        Map<String, Object> stats = new HashMap<>();
        List<Map<String, Object>> items = new ArrayList<>();

        // Track counts
        int builtInCount = 0;
        int userDefinedCount = 0;
        int currentPosition = 0;

        // Parse continuation token
        if (continuationToken != null && !continuationToken.isEmpty()) {
            String[] parts = continuationToken.split(":");
            if (parts.length == 3) {
                try {
                    builtInCount = Integer.parseInt(parts[0]);
                    userDefinedCount = Integer.parseInt(parts[1]);
                    currentPosition = Integer.parseInt(parts[2]);
                } catch (NumberFormatException e) {
                    Msg.warn(this, "Invalid continuation token: " + continuationToken);
                }
            }
        }

        // Get data type iterator
        Iterator<ghidra.program.model.data.DataType> dtIterator = program.getDataTypeManager().getAllDataTypes();

        // Skip to current position
        int skipped = 0;
        while (dtIterator.hasNext() && skipped < currentPosition) {
            dtIterator.next();
            skipped++;
        }

        // Process data types with time and count limits
        int processed = 0;
        long startTime = System.currentTimeMillis();
        final long MAX_PROCESSING_TIME = 25000; // 25 seconds

        while (dtIterator.hasNext() && processed < limit) {
            // Check time constraint
            if (System.currentTimeMillis() - startTime > MAX_PROCESSING_TIME) {
                break;
            }

            ghidra.program.model.data.DataType dt = dtIterator.next();
            currentPosition++;

            // Update counts
            if (dt.getSourceArchive().getArchiveType() == ghidra.program.model.data.ArchiveType.BUILT_IN) {
                builtInCount++;
            } else {
                userDefinedCount++;

                // Add details for user-defined data types only (to keep response size manageable)
                if (items.size() < 100) { // Limit to first 100
                    Map<String, Object> dtData = new HashMap<>();
                    dtData.put("name", dt.getName());
                    dtData.put("category", dt.getCategoryPath().getPath());
                    dtData.put("size", dt.getLength());
                    items.add(dtData);
                }
            }

            processed++;
        }

        // Determine if there's more data
        boolean isComplete = !dtIterator.hasNext();

        // Build stats
        stats.put("builtInCount", builtInCount);
        stats.put("userDefinedCount", userDefinedCount);
        stats.put("totalCount", builtInCount + userDefinedCount);

        Map<String, Object> response = new HashMap<>();
        response.put("dataTypeStats", stats);
        response.put("items", !items.isEmpty() ? items : Collections.emptyList());
        response.put("processedCount", processed);
        response.put("isComplete", isComplete);
        response.put("continuationToken", isComplete ? "" : builtInCount + ":" + userDefinedCount + ":" + currentPosition);

        return createSuccessResponse(response);
    }
    
    /**
     * Creates a standardized success response
     * 
     * @param data The data to include in the response
     * @return Map representing the success response
     */
    private Map<String, Object> createSuccessResponse(Object data) {
        Map<String, Object> response = new HashMap<>();
        
        // Standard top-level structure
        response.put("status", "success");
        response.put("data", data);
        
        return response;
    }
}
