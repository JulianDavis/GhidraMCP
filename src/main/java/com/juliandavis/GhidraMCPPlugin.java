package com.juliandavis;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data."
)
public class GhidraMCPPlugin extends Plugin {

    private HttpServer server;
    private EmulatorHttpHandler emulatorHandler;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin loaded!");
        try {
            startServer();
        }
        catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
    }
    
    /**
     * Get the HTTP server instance
     */
    public HttpServer getServer() {
        return server;
    }

    private void startServer() throws IOException {
        int port = 8080;
        server = HttpServer.create(new InetSocketAddress(port), 0);

        // Each listing endpoint uses offset & limit from query params:
        server.createContext("/methods", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendJsonResponse(exchange, getAllFunctionNames(offset, limit));
        });

        server.createContext("/classes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendJsonResponse(exchange, getAllClassNames(offset, limit));
        });

        server.createContext("/decompile", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            Map<String, Object> response = new HashMap<>();
            response.put("function", name);
            response.put("decompiled", decompileFunctionByName(name));
            sendJsonResponse(exchange, response);
        });

        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            boolean success = renameFunction(oldName, newName);

            Map<String, Object> response = new HashMap<>();
            response.put("success", success);
            response.put("oldName", oldName);
            response.put("newName", newName);
            response.put("message", success ? "Renamed successfully" : "Rename failed");

            sendJsonResponse(exchange, response);
        });

        server.createContext("/renameData", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String newName = params.get("newName");
            boolean success = renameDataAtAddress(address, newName);

            Map<String, Object> response = new HashMap<>();
            response.put("success", success);
            response.put("address", address);
            response.put("newName", newName);
            response.put("message", "Rename data attempted");

            sendJsonResponse(exchange, response);
        });

        server.createContext("/segments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendJsonResponse(exchange, listSegments(offset, limit));
        });

        server.createContext("/imports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendJsonResponse(exchange, listImports(offset, limit));
        });

        server.createContext("/exports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendJsonResponse(exchange, listExports(offset, limit));
        });

        server.createContext("/namespaces", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendJsonResponse(exchange, listNamespaces(offset, limit));
        });

        server.createContext("/data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendJsonResponse(exchange, listDefinedData(offset, limit));
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendJsonResponse(exchange, searchFunctionsByName(searchTerm, offset, limit));
        });

        server.createContext("/programInfo", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            boolean includeDetailedStats = "full".equals(qparams.get("detail"));
            sendJsonResponse(exchange, getProgramMetadata(includeDetailedStats));
        });

        // Add specialized time-bounded stats endpoints
        server.createContext("/programInfo/functionStats", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String continuationToken = qparams.get("continuationToken");
            int limit = parseIntOrDefault(qparams.get("limit"), 5000);
            sendJsonResponse(exchange, getFunctionStats(continuationToken, limit));
        });

        server.createContext("/programInfo/symbolStats", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String continuationToken = qparams.get("continuationToken");
            int limit = parseIntOrDefault(qparams.get("limit"), 5000);
            String symbolType = qparams.get("symbolType"); // Optional filter
            sendJsonResponse(exchange, getSymbolStats(continuationToken, limit, symbolType));
        });

        server.createContext("/programInfo/dataTypeStats", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String continuationToken = qparams.get("continuationToken");
            int limit = parseIntOrDefault(qparams.get("limit"), 5000);
            sendJsonResponse(exchange, getDataTypeStats(continuationToken, limit));
        });

        server.createContext("/xrefs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendJsonResponse(exchange, getReferencesAtAddress(address));
        });

        server.createContext("/disassemble", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int length = parseIntOrDefault(qparams.get("length"), 10);  // Default to 10 instructions
            sendJsonResponse(exchange, getDisassemblyAtAddress(address, length));
        });

        server.createContext("/disassembleFunction", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendJsonResponse(exchange, getDisassemblyForFunction(name));
        });

        server.createContext("/setComment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            int commentType = parseIntOrDefault(params.get("type"), CodeUnit.EOL_COMMENT); // Default to end-of-line comment

            sendJsonResponse(exchange, setCommentAtAddress(address, comment, commentType));
        });

        // Memory pattern search endpoint
        server.createContext("/memory/searchPattern", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String patternHex = params.get("pattern");
            boolean searchExecutable = Boolean.parseBoolean(params.getOrDefault("executable", "false"));
            boolean searchReadable = Boolean.parseBoolean(params.getOrDefault("readable", "true"));
            boolean caseSensitive = Boolean.parseBoolean(params.getOrDefault("caseSensitive", "true"));
            int maxResults = Integer.parseInt(params.getOrDefault("maxResults", "100"));
            
            sendJsonResponse(exchange, searchMemoryPattern(patternHex, searchExecutable, searchReadable, caseSensitive, maxResults));
        });
        
        // Memory cross-reference finder endpoint (scan memory for potential references)
        server.createContext("/memory/findPotentialReferences", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String targetAddress = params.get("address");
            boolean searchExecutable = Boolean.parseBoolean(params.getOrDefault("executable", "false"));
            boolean searchReadable = Boolean.parseBoolean(params.getOrDefault("readable", "true"));
            int maxResults = Integer.parseInt(params.getOrDefault("maxResults", "100"));
            
            sendJsonResponse(exchange, findPotentialMemoryReferences(targetAddress, searchExecutable, searchReadable, maxResults));
        });
        
        // Known references finder endpoint (using Ghidra's ReferenceManager)
        server.createContext("/memory/getKnownReferences", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String targetAddress = params.get("address");
            
            sendJsonResponse(exchange, getKnownMemoryReferences(targetAddress));
        });
        
        // Combined references finder endpoint (both known and potential)
        server.createContext("/memory/getAllReferences", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String targetAddress = params.get("address");
            boolean includeMemoryScan = Boolean.parseBoolean(params.getOrDefault("includeMemoryScan", "true"));
            boolean searchExecutable = Boolean.parseBoolean(params.getOrDefault("executable", "false"));
            boolean searchReadable = Boolean.parseBoolean(params.getOrDefault("readable", "true"));
            int maxResults = Integer.parseInt(params.getOrDefault("maxResults", "100"));
            
            sendJsonResponse(exchange, getAllMemoryReferences(
                targetAddress, includeMemoryScan, searchExecutable, searchReadable, maxResults));
        });

        // Data Type endpoints
        server.createContext("/dataTypes/search", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchPattern = qparams.get("query");
            String categoryPath = qparams.get("category");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            
            sendJsonResponse(exchange, DataTypeService.searchDataTypes(getCurrentProgram(), searchPattern, categoryPath, offset, limit));
        });
        
        server.createContext("/dataTypes/category", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String categoryPath = qparams.get("path");
            
            sendJsonResponse(exchange, DataTypeService.getDataTypeCategory(getCurrentProgram(), categoryPath));
        });
        
        server.createContext("/dataTypes/createPrimitive", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String dataTypeName = params.get("dataType");
            String address = params.get("address");
            
            sendJsonResponse(exchange, DataTypeService.createPrimitiveDataType(getCurrentProgram(), dataTypeName, address));
        });
        
        server.createContext("/dataTypes/createString", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String stringType = params.get("stringType");
            String address = params.get("address");
            int length = parseIntOrDefault(params.get("length"), -1);
            
            sendJsonResponse(exchange, DataTypeService.createStringDataType(getCurrentProgram(), stringType, address, length));
        });
        
        server.createContext("/dataTypes/createArray", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String elementType = params.get("elementType");
            String address = params.get("address");
            int numElements = parseIntOrDefault(params.get("numElements"), 1);
            
            sendJsonResponse(exchange, DataTypeService.createArrayDataType(getCurrentProgram(), elementType, address, numElements));
        });
        
        server.createContext("/dataTypes/createStructure", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String name = params.get("name");
            String description = params.get("description");
            boolean packed = Boolean.parseBoolean(params.getOrDefault("packed", "false"));
            int alignment = parseIntOrDefault(params.get("alignment"), 0);
            
            sendJsonResponse(exchange, DataTypeService.createStructureDataType(getCurrentProgram(), name, description, packed, alignment));
        });
        
        server.createContext("/dataTypes/addFieldToStructure", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String structureName = params.get("structureName");
            String fieldName = params.get("fieldName");
            String fieldType = params.get("fieldType");
            String comment = params.get("comment");
            
            // Get offset parameter if provided, otherwise -1 indicates "append to end"
            int offset = -1;
            if (params.containsKey("offset")) {
                try {
                    offset = Integer.parseInt(params.get("offset"));
                } catch (NumberFormatException e) {
                    Msg.warn(this, "Invalid offset value: " + params.get("offset"));
                }
            }
            
            if (offset >= 0) {
                // Use specified offset
                sendJsonResponse(exchange, DataTypeService.addFieldToStructure(getCurrentProgram(), structureName, fieldName, fieldType, comment, offset));
            } else {
                // Find the structure first to calculate its length (append to end)
                DataType structureType = DataTypeService.findDataType(getCurrentProgram(), structureName);
                if (structureType instanceof Structure) {
                    Structure structure = (Structure) structureType;
                    int appendOffset = structure.getLength();
                    sendJsonResponse(exchange, DataTypeService.addFieldToStructure(getCurrentProgram(), structureName, fieldName, fieldType, comment, appendOffset));
                } else {
                    // Structure not found or not a structure - pass offset 0 and let error handling in service handle it
                    sendJsonResponse(exchange, DataTypeService.addFieldToStructure(getCurrentProgram(), structureName, fieldName, fieldType, comment, 0));
                }
            }
        });
        
        server.createContext("/dataTypes/applyStructure", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String structureName = params.get("structureName");
            String address = params.get("address");
            
            sendJsonResponse(exchange, DataTypeService.applyStructureToMemory(getCurrentProgram(), structureName, address));
        });
        
        server.createContext("/dataTypes/createEnum", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String name = params.get("name");
            int valueSize = parseIntOrDefault(params.get("valueSize"), 4);
            String description = params.get("description");
            
            // Parse values map from comma-separated name:value pairs
            Map<String, Long> values = new HashMap<>();
            String valuesStr = params.get("values");
            if (valuesStr != null && !valuesStr.isEmpty()) {
                for (String pair : valuesStr.split(",")) {
                    String[] parts = pair.split(":");
                    if (parts.length == 2) {
                        try {
                            values.put(parts[0].trim(), Long.parseLong(parts[1].trim()));
                        } catch (NumberFormatException e) {
                            Msg.warn(this, "Invalid enum value: " + pair);
                        }
                    }
                }
            }
            
            sendJsonResponse(exchange, DataTypeService.createEnumDataType(getCurrentProgram(), name, valueSize, values, description));
        });
        
        server.createContext("/dataTypes/applyEnum", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String enumName = params.get("enumName");
            String address = params.get("address");
            
            sendJsonResponse(exchange, DataTypeService.applyEnumToMemory(getCurrentProgram(), enumName, address));
        });
        
        server.createContext("/dataTypes/delete", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String name = params.get("name");
            
            sendJsonResponse(exchange, DataTypeService.deleteDataType(getCurrentProgram(), name));
        });
        
        // Initialize and register emulator endpoints
        emulatorHandler = new EmulatorHttpHandler(this);
        emulatorHandler.registerEndpoints();
        
        server.setExecutor(null);
        new Thread(() -> {
            server.start();
            Msg.info(this, "GhidraMCP HTTP server started on port " + port);
        }, "GhidraMCP-HTTP-Server").start();
    }

    // ----------------------------------------------------------------------------------
    // Pagination-aware listing methods
    // ----------------------------------------------------------------------------------

    private Map<String, Object> getAllFunctionNames(int offset, int limit) {
        Program program = getCurrentProgram();
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
        return createPaginatedResponse(functions, allFunctions.size(), offset, limit);
    }

    private Map<String, Object> getAllClassNames(int offset, int limit) {
        Program program = getCurrentProgram();
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
        return createPaginatedResponse(classes, sortedNames.size(), offset, limit);
    }

    private Map<String, Object> listSegments(int offset, int limit) {
        Program program = getCurrentProgram();
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
        return createPaginatedResponse(segments, blocks.size(), offset, limit);
    }

    private Map<String, Object> listImports(int offset, int limit) {
        Program program = getCurrentProgram();
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
        return createPaginatedResponse(imports, externalSymbols.size(), offset, limit);
    }

    private Map<String, Object> listExports(int offset, int limit) {
        Program program = getCurrentProgram();
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
        return createPaginatedResponse(exports, exportSymbols.size(), offset, limit);
    }

    private Map<String, Object> listNamespaces(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        Set<Namespace> namespaceSet = new HashSet<>();

        // Collect all namespaces
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
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
        return createPaginatedResponse(namespaces, sortedNamespaces.size(), offset, limit);
    }

    private Map<String, Object> listDefinedData(int offset, int limit) {
        Program program = getCurrentProgram();
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
        return createPaginatedResponse(dataItems, allData.size(), offset, limit);
    }

    private Map<String, Object> searchFunctionsByName(String searchTerm, int offset, int limit) {
        Program program = getCurrentProgram();
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
        return createPaginatedResponse(functions, matchingFunctions.size(), offset, limit);
    }

    /**
     * Get disassembly listing for a specific function by name
     */
    private Map<String, Object> getDisassemblyForFunction(String name) {
        Program program = getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        if (name == null || name.isEmpty()) {
            return createErrorResponse("Function name is required");
        }

        try {
            // Find the function by name
            Function function = null;
            for (Function func : program.getFunctionManager().getFunctions(true)) {
                if (func.getName().equals(name)) {
                    function = func;
                    break;
                }
            }

            if (function == null) {
                return createErrorResponse("Function not found: " + name);
            }

            // Get function boundaries
            Address start = function.getEntryPoint();
            Address end = function.getBody().getMaxAddress();

            // Use the address range to get disassembly
            return getDisassemblyInRange(start, end, function);

        } catch (Exception e) {
            Msg.error(this, "Error getting disassembly for function " + name, e);
            return createErrorResponse("Error: " + e.getMessage());
        }
    }

    /**
     * Get disassembly at a specific address for a given number of instructions
     */
    private Map<String, Object> getDisassemblyAtAddress(String addressStr, int instructionCount) {
        Program program = getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return createErrorResponse("Address is required");
        }

        if (instructionCount <= 0) {
            return createErrorResponse("Instruction count must be positive");
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);

            // Determine the containing function (if any)
            Function function = program.getFunctionManager().getFunctionContaining(address);

            // Get all instructions starting from the given address
            List<Map<String, Object>> instructions = new ArrayList<>();
            Listing listing = program.getListing();
            int count = 0;

            Address currentAddress = address;
            while (count < instructionCount) {
                if (currentAddress == null || !program.getMemory().contains(currentAddress)) {
                    break;
                }

                Instruction instr = listing.getInstructionAt(currentAddress);
                if (instr == null) {
                    break;
                }

                Map<String, Object> instrData = createInstructionData(instr, function);
                instructions.add(instrData);

                try {
                    currentAddress = instr.getAddress().add(instr.getLength());
                } catch (Exception e) {
                    break;
                }
                count++;
            }

            Map<String, Object> result = new HashMap<>();
            result.put("address", address.toString());
            result.put("instructions", instructions);
            result.put("count", instructions.size());
            if (function != null) {
                result.put("function", function.getName());
            }
            result.put("success", true);

            return result;

        } catch (Exception e) {
            Msg.error(this, "Error getting disassembly for address " + addressStr, e);
            return createErrorResponse("Invalid address or error: " + e.getMessage());
        }
    }

    /**
     * Get disassembly for an address range (internal method)
     */
    private Map<String, Object> getDisassemblyInRange(Address start, Address end, Function function) throws MemoryAccessException {
        Program program = getCurrentProgram();
        Listing listing = program.getListing();

        List<Map<String, Object>> instructions = new ArrayList<>();

        Address currentAddress = start;
        while (currentAddress != null && currentAddress.compareTo(end) <= 0) {
            if (!program.getMemory().contains(currentAddress)) {
                // Skip to next address
                currentAddress = currentAddress.add(1);
                continue;
            }

            Instruction instr = listing.getInstructionAt(currentAddress);
            if (instr == null) {
                currentAddress = currentAddress.add(1);
                continue;
            }

            Map<String, Object> instrData = createInstructionData(instr, function);
            instructions.add(instrData);

            // Go to the next instruction
            try {
                currentAddress = instr.getAddress().add(instr.getLength());
            } catch (Exception e) {
                currentAddress = currentAddress.add(1);
            }
        }

        Map<String, Object> result = new HashMap<>();
        result.put("start", start.toString());
        result.put("end", end.toString());
        result.put("instructions", instructions);
        result.put("count", instructions.size());
        if (function != null) {
            result.put("function", function.getName());
            result.put("signature", function.getSignature().toString());
        }
        result.put("success", true);

        return result;
    }

    /**
     * Create a map of instruction data (internal helper)
     */
    private Map<String, Object> createInstructionData(Instruction instr, Function function) throws MemoryAccessException {
        Map<String, Object> instrData = new HashMap<>();
        instrData.put("address", instr.getAddress().toString());
        instrData.put("bytes", bytesToHexString(instr.getParsedBytes()));
        instrData.put("mnemonic", instr.getMnemonicString());

        // Get the full representation with operands
        String representation = instr.toString();
        instrData.put("representation", representation);

        // Extract operands info
        List<Map<String, Object>> operands = new ArrayList<>();
        for (int i = 0; i < instr.getNumOperands(); i++) {
            Map<String, Object> operandData = new HashMap<>();
            operandData.put("index", i);
            operandData.put("text", instr.getDefaultOperandRepresentation(i));
            operandData.put("type", instr.getOperandType(i));

            // For references, include the target information
            int opType = instr.getOperandType(i);
            boolean hasReference = false;

            // Check if this operand has any references
            Reference[] refs = instr.getOperandReferences(i);
            if (refs != null && refs.length > 0) {
                hasReference = true;

                List<Map<String, Object>> refList = new ArrayList<>();

                for (Reference ref : refs) {
                    Map<String, Object> refData = new HashMap<>();
                    refData.put("toAddress", ref.getToAddress().toString());
                    refData.put("type", ref.getReferenceType().toString());

                    // Add target information if it's a function
                    Function targetFunc = getCurrentProgram().getFunctionManager().getFunctionAt(ref.getToAddress());
                    if (targetFunc != null) {
                        refData.put("toFunction", targetFunc.getName());
                    }

                    refList.add(refData);
                }

                operandData.put("references", refList);
            }

            operands.add(operandData);
        }
        instrData.put("operands", operands);

        // Add any comments
        String comment = getCurrentProgram().getListing().getComment(
                CodeUnit.PLATE_COMMENT, instr.getAddress());
        if (comment != null && !comment.isEmpty()) {
            instrData.put("plateComment", comment);
        }

        comment = getCurrentProgram().getListing().getComment(
                CodeUnit.PRE_COMMENT, instr.getAddress());
        if (comment != null && !comment.isEmpty()) {
            instrData.put("preComment", comment);
        }

        comment = getCurrentProgram().getListing().getComment(
                CodeUnit.EOL_COMMENT, instr.getAddress());
        if (comment != null && !comment.isEmpty()) {
            instrData.put("eolComment", comment);
        }

        comment = getCurrentProgram().getListing().getComment(
                CodeUnit.POST_COMMENT, instr.getAddress());
        if (comment != null && !comment.isEmpty()) {
            instrData.put("postComment", comment);
        }

        // If this instruction is the entry point of a function, mark it
        Function funcAtAddr = getCurrentProgram().getFunctionManager().getFunctionAt(instr.getAddress());
        if (funcAtAddr != null) {
            instrData.put("isEntryPoint", true);
            instrData.put("functionName", funcAtAddr.getName());
        }

        // Determine relative position in the containing function
        if (function != null) {
            long offset = instr.getAddress().subtract(function.getEntryPoint());
            instrData.put("functionOffset", offset);
        }

        return instrData;
    }

    /**
     * Convert byte array to hex string (internal helper)
     */
    private String bytesToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Find potential memory locations that reference a specific address by scanning memory.
     * This can find references not tracked by Ghidra, but is much slower and may produce false positives.
     * 
     * @param targetAddressStr The target address to find references to (as a string)
     * @param searchExecutable Whether to search only in executable memory
     * @param searchReadable Whether to search only in readable memory
     * @param maxResults Maximum number of results to return
     * @return Map containing the search results
     */
    private Map<String, Object> findPotentialMemoryReferences(
            String targetAddressStr,
            boolean searchExecutable,
            boolean searchReadable,
            int maxResults) {
        
        Program program = getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        if (targetAddressStr == null || targetAddressStr.isEmpty()) {
            return createErrorResponse("Target address is required");
        }
        
        try {
            // Validate the address
            Address targetAddress = program.getAddressFactory().getAddress(targetAddressStr);
            if (targetAddress == null) {
                return createErrorResponse("Invalid target address: " + targetAddressStr);
            }
            
            // Get the search results
            List<Map<String, Object>> results = MemoryCrossReferenceService.findPotentialReferences(
                    program, 
                    targetAddressStr, 
                    searchExecutable, 
                    searchReadable, 
                    maxResults, 
                    TaskMonitor.DUMMY);
            
            // Add existing references from the reference manager for completeness
            List<Map<String, Object>> existingRefs = new ArrayList<>();
            ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(targetAddress);
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Map<String, Object> refInfo = new HashMap<>();
                refInfo.put("referenceAddress", ref.getFromAddress().toString());
                refInfo.put("targetAddress", ref.getToAddress().toString());
                refInfo.put("referenceType", ref.getReferenceType().toString());
                refInfo.put("isPrimary", ref.isPrimary());
                refInfo.put("isExisting", true); // Mark as an existing reference
                
                // Skip if this reference is already in our scanned results
                boolean duplicate = false;
                for (Map<String, Object> result : results) {
                    if (result.get("referenceAddress").equals(refInfo.get("referenceAddress"))) {
                        // Update the existing entry
                        result.put("referenceType", refInfo.get("referenceType"));
                        result.put("isPrimary", refInfo.get("isPrimary"));
                        result.put("isExisting", true);
                        duplicate = true;
                        break;
                    }
                }
                
                if (!duplicate) {
                    existingRefs.add(refInfo);
                }
            }
            
            // Add existing references to results
            results.addAll(existingRefs);
            
            // Sort results by address
            results.sort((a, b) -> {
                String addrA = (String) a.get("referenceAddress");
                String addrB = (String) b.get("referenceAddress");
                return addrA.compareTo(addrB);
            });
            
            // Apply result limit if needed
            if (maxResults > 0 && results.size() > maxResults) {
                results = results.subList(0, maxResults);
            }
            
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("targetAddress", targetAddressStr);
            response.put("potentialReferences", results);
            response.put("count", results.size());
            
            if (maxResults > 0 && results.size() >= maxResults) {
                response.put("limitReached", true);
                response.put("message", "Maximum result limit reached. Use maxResults parameter to adjust.");
            }
            
            response.put("searchCriteria", Map.of(
                "searchExecutable", searchExecutable,
                "searchReadable", searchReadable,
                "maxResults", maxResults
            ));
            
            return response;
        } catch (Exception e) {
            Msg.error(this, "Error finding potential memory references", e);
            return createErrorResponse("Error finding potential memory references: " + e.getMessage());
        }
    }
    
    /**
     * Get known references to a target address using Ghidra's ReferenceManager.
     * This is fast and should be the primary method for finding references.
     * 
     * @param targetAddressStr The target address to find references to (as a string)
     * @return Map containing the known references
     */
    private Map<String, Object> getKnownMemoryReferences(String targetAddressStr) {
        Program program = getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        if (targetAddressStr == null || targetAddressStr.isEmpty()) {
            return createErrorResponse("Target address is required");
        }
        
        try {
            // Validate the address
            Address targetAddress = program.getAddressFactory().getAddress(targetAddressStr);
            if (targetAddress == null) {
                return createErrorResponse("Invalid target address: " + targetAddressStr);
            }
            
            // Get the known references from the reference manager
            List<Map<String, Object>> knownRefs = MemoryCrossReferenceService.getKnownReferences(
                    program, targetAddressStr, TaskMonitor.DUMMY);
            
            // Sort results by address
            knownRefs.sort((a, b) -> {
                String addrA = (String) a.get("referenceAddress");
                String addrB = (String) b.get("referenceAddress");
                return addrA.compareTo(addrB);
            });
            
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("targetAddress", targetAddressStr);
            response.put("knownReferences", knownRefs);
            response.put("count", knownRefs.size());
            
            // Get code unit at target address for context
            CodeUnit targetCodeUnit = program.getListing().getCodeUnitAt(targetAddress);
            if (targetCodeUnit != null) {
                response.put("targetCodeUnitType", targetCodeUnit.getClass().getSimpleName());
                response.put("targetMnemonic", targetCodeUnit.getMnemonicString());
            }
            
            // Check if target is a function
            Function func = program.getFunctionManager().getFunctionAt(targetAddress);
            if (func != null) {
                response.put("targetFunction", Map.of(
                    "name", func.getName(),
                    "signature", func.getSignature().toString(),
                    "returnType", func.getReturnType().toString()
                ));
            }
            
            return response;
        } catch (Exception e) {
            Msg.error(this, "Error finding known references", e);
            return createErrorResponse("Error finding known references: " + e.getMessage());
        }
    }
    
    /**
     * Find all references to a target address, both known and potential.
     * First gets references from Ghidra's ReferenceManager, then optionally scans memory.
     * 
     * @param targetAddressStr The target address to find references to (as a string)
     * @param includeMemoryScan Whether to include a memory scan for potential references
     * @param searchExecutable For memory scan: whether to search only in executable memory
     * @param searchReadable For memory scan: whether to search only in readable memory
     * @param maxResults For memory scan: maximum number of results to return
     * @return Map containing both known and potential references
     */
    private Map<String, Object> getAllMemoryReferences(
            String targetAddressStr,
            boolean includeMemoryScan,
            boolean searchExecutable,
            boolean searchReadable,
            int maxResults) {
        
        Program program = getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        if (targetAddressStr == null || targetAddressStr.isEmpty()) {
            return createErrorResponse("Target address is required");
        }
        
        try {
            // Get the combined search results
            Map<String, Object> results = MemoryCrossReferenceService.findAllReferences(
                    program, 
                    targetAddressStr,
                    includeMemoryScan,
                    searchExecutable, 
                    searchReadable, 
                    maxResults, 
                    TaskMonitor.DUMMY);
            
            // Add a timestamp for client caching
            results.put("timestamp", System.currentTimeMillis());
            
            return results;
        } catch (Exception e) {
            Msg.error(this, "Error finding all memory references", e);
            return createErrorResponse("Error finding all memory references: " + e.getMessage());
        }
    }
    
    /**
     * Search for a pattern in memory
     * 
     * @param patternHex The pattern to search for as a hex string
     * @param searchExecutable Whether to search only in executable memory
     * @param searchReadable Whether to search only in readable memory
     * @param caseSensitive Whether the search is case sensitive
     * @param maxResults Maximum number of results to return
     * @return Map containing the search results
     */
    private Map<String, Object> searchMemoryPattern(
            String patternHex,
            boolean searchExecutable,
            boolean searchReadable,
            boolean caseSensitive,
            int maxResults) {
        
        Program program = getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }
        
        if (patternHex == null || patternHex.isEmpty()) {
            return createErrorResponse("Pattern is required");
        }
        
        // Remove any whitespace or "0x" prefix
        patternHex = patternHex.trim().replaceAll("\\s", "");
        if (patternHex.toLowerCase().startsWith("0x")) {
            patternHex = patternHex.substring(2);
        }
        
        // Validate hex string
        if (!patternHex.matches("[0-9A-Fa-f]*")) {
            return createErrorResponse("Invalid hex pattern: must contain only hex characters");
        }
        
        try {
            // Get the search results
            List<Map<String, Object>> results = MemoryPatternSearchService.searchForPattern(
                    program, 
                    patternHex, 
                    searchExecutable, 
                    searchReadable, 
                    caseSensitive, 
                    maxResults, 
                    TaskMonitor.DUMMY);
            
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("pattern", patternHex);
            response.put("matches", results);
            response.put("count", results.size());
            
            if (results.size() >= maxResults) {
                response.put("limitReached", true);
                response.put("message", "Maximum result limit reached. Use maxResults parameter to adjust.");
            }
            
            response.put("searchCriteria", Map.of(
                "searchExecutable", searchExecutable,
                "searchReadable", searchReadable,
                "caseSensitive", caseSensitive,
                "maxResults", maxResults
            ));
            
            return response;
        } catch (Exception e) {
            Msg.error(this, "Error searching memory pattern", e);
            return createErrorResponse("Error searching memory pattern: " + e.getMessage());
        }
    }
    
    /**
     * Set a comment at the specified address
     */
    private Map<String, Object> setCommentAtAddress(String addressStr, String comment, int commentType) {
        Program program = getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return createErrorResponse("Address is required");
        }

        // Validate comment type
        if (commentType != CodeUnit.PLATE_COMMENT &&
            commentType != CodeUnit.PRE_COMMENT &&
            commentType != CodeUnit.EOL_COMMENT &&
            commentType != CodeUnit.POST_COMMENT &&
            commentType != CodeUnit.REPEATABLE_COMMENT) {

            return createErrorResponse("Invalid comment type: " + commentType);
        }

        AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Set comment");
                try {
                    Address address = program.getAddressFactory().getAddress(addressStr);

                    // Get the code unit at this address (could be an instruction or data)
                    CodeUnit codeUnit = program.getListing().getCodeUnitAt(address);
                    if (codeUnit != null) {
                        codeUnit.setComment(commentType, comment);
                        successFlag.set(true);
                    } else {
                        Msg.warn(this, "No code unit found at address: " + addressStr);
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error setting comment at address " + addressStr, e);
                }
                finally {
                    program.endTransaction(tx, true);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set comment on Swing thread", e);
            return createErrorResponse("Error: " + e.getMessage());
        }

        Map<String, Object> result = new HashMap<>();
        result.put("success", successFlag.get());
        result.put("address", addressStr);
        result.put("commentType", commentType);

        // If we know comment type names, include them
        String commentTypeName;
        switch (commentType) {
            case CodeUnit.PLATE_COMMENT:
                commentTypeName = "PLATE";
                break;
            case CodeUnit.PRE_COMMENT:
                commentTypeName = "PRE";
                break;
            case CodeUnit.EOL_COMMENT:
                commentTypeName = "EOL";
                break;
            case CodeUnit.POST_COMMENT:
                commentTypeName = "POST";
                break;
            case CodeUnit.REPEATABLE_COMMENT:
                commentTypeName = "REPEATABLE";
                break;
            default:
                commentTypeName = "UNKNOWN";
        }
        result.put("commentTypeName", commentTypeName);

        if (!successFlag.get()) {
            result.put("message", "Failed to set comment - no code unit at address");
        }

        return result;
    }

    /**
     * Get all references to and from the specified address
     */
    private Map<String, Object> getReferencesAtAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return createErrorResponse("Address is required");
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);

            // Get all references to this address (where this is the target)
            List<Map<String, Object>> referencesToHere = new ArrayList<>();
            ReferenceIterator refsToIter = program.getReferenceManager().getReferencesTo(address);
            while (refsToIter.hasNext()) {
                Reference ref = refsToIter.next();
                Map<String, Object> reference = new HashMap<>();
                reference.put("fromAddress", ref.getFromAddress().toString());
                reference.put("toAddress", ref.getToAddress().toString());
                reference.put("type", ref.getReferenceType().toString());
                reference.put("isData", !ref.isMemoryReference());
                reference.put("isPrimary", ref.isPrimary());

                // Add source context if it's a function
                Function fromFunc = program.getFunctionManager().getFunctionAt(ref.getFromAddress());
                if (fromFunc != null) {
                    reference.put("fromFunction", fromFunc.getName());
                    reference.put("fromFunctionOffset",
                            ref.getFromAddress().subtract(fromFunc.getEntryPoint()));
                }

                referencesToHere.add(reference);
            }

            // Get all references from this address (where this is the source)
            List<Map<String, Object>> referencesFromHere = new ArrayList<>();
            Reference[] refsFrom = program.getReferenceManager().getReferencesFrom(address);
            for (Reference ref : refsFrom) {
                Map<String, Object> reference = new HashMap<>();
                reference.put("fromAddress", ref.getFromAddress().toString());
                reference.put("toAddress", ref.getToAddress().toString());
                reference.put("type", ref.getReferenceType().toString());
                reference.put("isData", !ref.isMemoryReference());
                reference.put("isPrimary", ref.isPrimary());

                // Add target context if it's a function
                Function toFunc = program.getFunctionManager().getFunctionAt(ref.getToAddress());
                if (toFunc != null) {
                    reference.put("toFunction", toFunc.getName());
                }

                referencesFromHere.add(reference);
            }

            Map<String, Object> result = new HashMap<>();
            result.put("address", address.toString());
            result.put("referencesToHere", referencesToHere);
            result.put("referencesFromHere", referencesFromHere);
            result.put("success", true);

            return result;

        } catch (Exception e) {
            Msg.error(this, "Error getting references for address " + addressStr, e);
            return createErrorResponse("Invalid address or error retrieving references: " + e.getMessage());
        }
    }

    // Cache for program metadata to avoid redundant calculations
    private Map<String, Object> cachedBasicMetadata = null;
    private Map<String, Object> cachedFullMetadata = null;
    private long lastModificationTime = 0;

    /**
     * Get detailed metadata about the currently loaded program
     *
     * @param includeDetailedStats Whether to include detailed statistics (which can be expensive to compute)
     * @return Map containing program metadata or error response
     */
    private Map<String, Object> getProgramMetadata(boolean includeDetailedStats) {
        Program program = getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        // Check if we can use cached data
        if (program.getModificationNumber() == lastModificationTime) {
            if (includeDetailedStats && cachedFullMetadata != null) {
                return Map.of("success", true, "programInfo", cachedFullMetadata);
            } else if (!includeDetailedStats && cachedBasicMetadata != null) {
                return Map.of("success", true, "programInfo", cachedBasicMetadata);
            }
        }

        // Update cache timestamp
        lastModificationTime = program.getModificationNumber();

        // Create metadata with appropriate level of detail
        Map<String, Object> metadata = new HashMap<>();

        // Basic program information (always include)
        addBasicProgramInfo(program, metadata);

        // Add detailed stats if requested
        if (includeDetailedStats) {
            addDetailedProgramStats(program, metadata);
            cachedFullMetadata = metadata;
        } else {
            cachedBasicMetadata = metadata;
        }

        return Map.of("success", true, "programInfo", metadata);
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
     * Get function statistics with time-bounded processing and continuation support
     *
     * @param continuationToken Token from a previous request to resume processing
     * @param limit Maximum number of functions to process in this request
     * @return Response with function statistics and continuation info
     */
    private Map<String, Object> getFunctionStats(String continuationToken, int limit) {
        Program program = getCurrentProgram();
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        Map<String, Object> response = new HashMap<>();
        Map<String, Object> stats = new HashMap<>();

        // Always include total count (fast operation)
        FunctionManager functionManager = program.getFunctionManager();
        stats.put("totalCount", functionManager.getFunctionCount());

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

        Iterator<Function> it = functionManager.getFunctions(true);
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
        response.put("stats", stats);
        response.put("isComplete", isComplete);
        if (!isComplete) {
            response.put("continuationToken", externalCount + ":" + internalCount);
        }

        return Map.of(
                "success", true,
                "functionStats", stats,
                "isComplete", isComplete,
                "continuationToken", isComplete ? "" : externalCount + ":" + internalCount
        );
    }

    /**
     * Add detailed program statistics (potentially slow for large programs)
     */
    private void addDetailedProgramStats(Program program, Map<String, Object> metadata) {
        // Enhance function statistics - use fast total count only
        Map<String, Object> functionStats = (Map<String, Object>) metadata.get("functions");
        FunctionManager functionManager = program.getFunctionManager();

        // Only include the total count here, detailed counts should be fetched separately
        functionStats.put("note", "For detailed function statistics, use the /programInfo/functionStats endpoint");

        // Enhance symbol statistics
        Map<String, Object> symbolStats = (Map<String, Object>) metadata.get("symbols");
        SymbolTable symbolTable = program.getSymbolTable();
        // Only include total counts in the basic metadata
        symbolStats.put("note", "For detailed symbol statistics, use the /programInfo/symbolStats endpoint");

        // Add placeholder for data types
        Map<String, Object> dataTypeStats = new HashMap<>();
        dataTypeStats.put("note", "For detailed data type statistics, use the /programInfo/dataTypeStats endpoint");
        metadata.put("dataTypes", dataTypeStats);
    }

    /**
     * Get symbol statistics with time-bounded processing and continuation support
     *
     * @param continuationToken Token from a previous request to resume processing
     * @param limit Maximum number of symbols to process in this request
     * @param symbolType Optional filter for a specific symbol type
     * @return Response with symbol statistics and continuation info
     */
    private Map<String, Object> getSymbolStats(String continuationToken, int limit, String symbolType) {
        Program program = getCurrentProgram();
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

        return Map.of(
            "success", true,
            "symbolStats", stats,
            "items", items.size() > 0 ? items : Collections.emptyList(),
            "processedCount", processed,
            "isComplete", isComplete,
            "continuationToken", isComplete ? "" : String.valueOf(currentPosition)
        );
    }

    /**
     * Get data type statistics with time-bounded processing and continuation support
     *
     * @param continuationToken Token from a previous request to resume processing
     * @param limit Maximum number of data types to process in this request
     * @return Response with data type statistics and continuation info
     */
    private Map<String, Object> getDataTypeStats(String continuationToken, int limit) {
        Program program = getCurrentProgram();
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

        return Map.of(
            "success", true,
            "dataTypeStats", stats,
            "items", !items.isEmpty() ? items : Collections.emptyList(),
            "processedCount", processed,
            "isComplete", isComplete,
            "continuationToken", isComplete ? "" : builtInCount + ":" + userDefinedCount + ":" + currentPosition
        );
    }

    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private String decompileFunctionByName(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result =
                    decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }

    private boolean renameFunction(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function via HTTP");
                try {
                    for (Function func : program.getFunctionManager().getFunctions(true)) {
                        if (func.getName().equals(oldName)) {
                            func.setName(newName, ghidra.program.model.symbol.SourceType.USER_DEFINED);
                            successFlag.set(true);
                            break;
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                }
                finally {
                    program.endTransaction(tx, successFlag.get());
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }
        return successFlag.get();
    }

    private boolean renameDataAtAddress(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    Listing listing = program.getListing();
                    Data data = listing.getDefinedDataAt(addr);
                    if (data != null) {
                        SymbolTable symTable = program.getSymbolTable();
                        Symbol symbol = symTable.getPrimarySymbol(addr);
                        if (symbol != null) {
                            symbol.setName(newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                        } else {
                            symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Rename data error", e);
                }
                finally {
                    program.endTransaction(tx, true);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }
        return successFlag.get();
    }

    // ----------------------------------------------------------------------------------
    // Utility: parse query params, parse post params, pagination, etc.
    // ----------------------------------------------------------------------------------

    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     * Properly URL-decodes parameter values
     */
    public Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery(); // e.g. offset=10&limit=100
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=", 2); // Split on first equals sign only
                if (kv.length == 2) {
                    // Properly URL-decode the parameter value
                    String key = kv[0];
                    String value = null;
                    try {
                        value = java.net.URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    } catch (IllegalArgumentException e) {
                        Msg.warn(this, "Invalid URL encoding for parameter " + key + ": " + e.getMessage());
                        value = kv[1]; // Use raw value as fallback
                    }
                    result.put(key, value);
                }
            }
        }
        return result;
    }

    /**
     * Parse post body form params, e.g. oldName=foo&newName=bar
     * Properly URL-decodes parameter values
     */
    public Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=", 2); // Split on first equals sign only
            if (kv.length == 2) {
                // Properly URL-decode the parameter value
                String key = kv[0];
                String value = java.net.URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                params.put(key, value);
            }
        }
        return params;
    }

    /**
     * Convert a list of strings into one big newline-delimited string, applying offset & limit.
     */
    private String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end   = Math.min(items.size(), offset + limit);

        if (start >= items.size()) {
            return ""; // no items in range
        }
        List<String> sub = items.subList(start, end);
        return String.join("\n", sub);
    }

    /**
     * Create a JSON-serialized error response
     */
    private Map<String, Object> createErrorResponse(String message) {
        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("error", message);
        return response;
    }

    /**
     * Create a paginated response with metadata
     */
    private Map<String, Object> createPaginatedResponse(List<?> items, int totalCount, int offset, int limit) {
        Map<String, Object> response = new HashMap<>();
        response.put("items", items);
        response.put("total", totalCount);
        response.put("offset", offset);
        response.put("limit", limit);
        response.put("success", true);
        return response;
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
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
     * Simple JSON serialization. In a real application, you'd use a proper library like Gson.
     */
    private String convertToJson(Object obj) {
        if (obj == null) {
            return "null";
        }

        if (obj instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) obj;
            StringBuilder sb = new StringBuilder();
            sb.append("{");
            boolean first = true;
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                if (!first) {
                    sb.append(",");
                }
                first = false;
                sb.append("\"").append(entry.getKey()).append("\":");
                sb.append(convertToJson(entry.getValue()));
            }
            sb.append("}");
            return sb.toString();
        }

        if (obj instanceof List) {
            @SuppressWarnings("unchecked")
            List<Object> list = (List<Object>) obj;
            StringBuilder sb = new StringBuilder();
            sb.append("[");
            boolean first = true;
            for (Object item : list) {
                if (!first) {
                    sb.append(",");
                }
                first = false;
                sb.append(convertToJson(item));
            }
            sb.append("]");
            return sb.toString();
        }

        if (obj instanceof String) {
            return "\"" + escapeJsonString((String) obj) + "\"";
        }

        if (obj instanceof Number || obj instanceof Boolean) {
            return obj.toString();
        }

        // For any other type, convert to string
        return "\"" + escapeJsonString(obj.toString()) + "\"";
    }

    /**
     * Escape special characters in JSON strings
     */
    private String escapeJsonString(String input) {
        if (input == null) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);

            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\b':
                    sb.append("\\b");
                    break;
                case '\f':
                    sb.append("\\f");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < ' ') {
                        // Control characters
                        String hex = Integer.toHexString(c);
                        sb.append("\\u");
                        sb.append("0".repeat(4 - hex.length()));
                        sb.append(hex);
                    } else {
                        sb.append(c);
                    }
            }
        }

        return sb.toString();
    }

    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    /**
     * Send a JSON response with proper content type
     */
    public void sendJsonResponse(HttpExchange exchange, Object data) throws IOException {
        String json = convertToJson(data);
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    @Override
    public void dispose() {
        if (server != null) {
            server.stop(0);
            Msg.info(this, "HTTP server stopped.");
        }
        super.dispose();
    }
}
