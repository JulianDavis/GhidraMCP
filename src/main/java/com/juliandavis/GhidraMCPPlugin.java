package com.juliandavis;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

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
                            func.setName(newName, SourceType.USER_DEFINED);
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
     */
    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery(); // e.g. offset=10&limit=100
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=");
                if (kv.length == 2) {
                    result.put(kv[0], kv[1]);
                }
            }
        }
        return result;
    }

    /**
     * Parse post body form params, e.g. oldName=foo&newName=bar
     */
    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=");
            if (kv.length == 2) {
                params.put(kv[0], kv[1]);
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
    private void sendJsonResponse(HttpExchange exchange, Object data) throws IOException {
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
