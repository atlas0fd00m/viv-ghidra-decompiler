// Ghidra headless script: Start the Vivisect-Ghidra bridge TCP server.
// This version ACTUALLY applies symbols from Vivisect (Mode 1 enrichment).
//
// @category VivGhidra
// @author UberNethers

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import ghidra.util.task.TaskMonitor;

import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.util.*;
import java.util.concurrent.*;

public class StartBridgeServer extends GhidraScript {

    private static final int DEFAULT_PORT = 13100;
    private static final int SHUTDOWN_PORT = 13199;
    private ServerSocket serverSocket;
    private ServerSocket shutdownSocket;
    private volatile boolean running = true;
    private ExecutorService pool;
    private List<Map<String, Object>> functionList;

    @Override
    protected void run() throws Exception {
        int port = DEFAULT_PORT;
        String portEnv = System.getenv("VIVGHIDRA_PORT");
        if (portEnv != null && !portEnv.isEmpty()) {
            try { port = Integer.parseInt(portEnv); } catch (Exception e) { }
        }

        // Collect function info
        functionList = new ArrayList<>();
        FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
        while (iter.hasNext()) {
            Function f = iter.next();
            Map<String, Object> info = new LinkedHashMap<>();
            info.put("name", f.getName());
            info.put("address", f.getEntryPoint().toString());
            info.put("size", f.getBody().getNumAddresses());
            functionList.add(info);
        }

        println("=== Vivisect-Ghidra Bridge Server (with symbol enrichment) ===");
        println("Program: " + currentProgram.getName());
        println("Functions found: " + functionList.size());

        // Start TCP server
        serverSocket = new ServerSocket(port);
        shutdownSocket = new ServerSocket(SHUTDOWN_PORT);
        pool = Executors.newCachedThreadPool();

        println("Bridge server listening on port " + port);

        while (running) {
            if (shutdownSocketConnected()) {
                running = false;
                break;
            }
            try {
                serverSocket.setSoTimeout(500);
                Socket client = serverSocket.accept();
                pool.submit(() -> handleClient(client));
            } catch (java.net.SocketTimeoutException e) { }
        }

        println("Shutting down bridge server...");
        pool.shutdownNow();
        serverSocket.close();
        shutdownSocket.close();
    }

    private boolean shutdownSocketConnected() {
        try {
            shutdownSocket.setSoTimeout(100);
            Socket s = shutdownSocket.accept();
            s.close();
            return true;
        } catch (Exception e) { return false; }
    }

    private void handleClient(Socket socket) {
        try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));
             BufferedWriter writer = new BufferedWriter(
                    new OutputStreamWriter(socket.getOutputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.trim().isEmpty()) continue;
                try {
                    Map<String, Object> request = parseJson(line);
                    int id = getInt(request, "id", 0);
                    String method = getString(request, "method", "");
                    Map<String, Object> params = getMap(request, "params");
                    try {
                        Object result = dispatch(method, params);
                        sendResponse(writer, id, result, null);
                    } catch (Exception e) {
                        sendResponse(writer, id, null, e.getMessage());
                    }
                } catch (Exception e) {
                    sendResponse(writer, 0, null, "Parse error: " + e.getMessage());
                }
            }
        } catch (IOException e) { }
    }

    private Object dispatch(String method, Map<String, Object> params) throws Exception {
        switch (method) {
            case "ping": {
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("pong", true);
                r.put("version", "1.0");
                return r;
            }
            case "get_status": {
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("program_loaded", true);
                r.put("program_name", currentProgram.getName());
                return r;
            }
            case "decompile_function":
                return decompileFunction(params);
            case "get_function_list": {
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("functions", functionList);
                r.put("success", true);
                return r;
            }
            case "apply_symbols":
                return applySymbols(params);
            case "set_comment":
                return setComment(params);
            case "rename_symbol":
                return renameSymbol(params);
            case "set_signature":
                return setSignature(params);
            default:
                throw new IllegalArgumentException("Unknown method: " + method);
        }
    }

    // ─── Symbol Application (Mode 1) ───

    @SuppressWarnings("unchecked")
    private Map<String, Object> applySymbols(Map<String, Object> params) {
        List<Object> symbols = (List<Object>) params.getOrDefault("symbols", new ArrayList<>());
        int applied = 0;
        int failed = 0;

        for (Object obj : symbols) {
            if (!(obj instanceof Map)) continue;
            Map<String, Object> sym = (Map<String, Object>) obj;
            try {
                String name = getString(sym, "name", "");
                String addrStr = getString(sym, "address", "");
                boolean isFunction = getBool(sym, "is_function", false);
                if (name.isEmpty() || addrStr.isEmpty()) { failed++; continue; }

                Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
                if (addr == null) { failed++; continue; }

                if (isFunction) {
                    FunctionManager fm = currentProgram.getFunctionManager();
                    Function func = fm.getFunctionAt(addr);
                    if (func != null) {
                        func.setName(name, SourceType.USER_DEFINED);
                    } else {
                        try {
                            func = fm.createFunction(name, addr, null, SourceType.USER_DEFINED);
                        } catch (Exception e) { failed++; continue; }
                    }

                    // Apply return type
                    String retType = getString(sym, "return_type", "");
                    if (!retType.isEmpty() && !retType.equals("void") && func != null) {
                        try {
                            DataType retDt = parseDataType(retType);
                            if (retDt != null) func.setReturnType(retDt, SourceType.USER_DEFINED);
                        } catch (Exception e) { }
                    }

                    // Apply parameter types
                    List<Object> paramTypes = (List<Object>) sym.getOrDefault("param_types", new ArrayList<>());
                    if (!paramTypes.isEmpty() && func != null) {
                        try {
                            java.util.List<Parameter> paramsList = new ArrayList<>();
                            for (int i = 0; i < paramTypes.size(); i++) {
                                DataType pdt = parseDataType(paramTypes.get(i).toString());
                                if (pdt != null) {
                                    paramsList.add(new ParameterImpl("param" + i, pdt, currentProgram));
                                }
                            }
                            if (!paramsList.isEmpty()) {
                                func.replaceParameters(paramsList,
                                    Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                                    true, SourceType.USER_DEFINED);
                            }
                        } catch (Exception e) { }
                    }
                    applied++;
                } else {
                    SymbolTable st = currentProgram.getSymbolTable();
                    st.createLabel(addr, name, SourceType.USER_DEFINED);
                    applied++;
                }
            } catch (Exception e) {
                failed++;
            }
        }

        // Save changes
        try {
            currentProgram.save("Apply Vivisect symbols", monitor);
        } catch (Exception e) { }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("applied", applied);
        result.put("failed", failed);
        result.put("success", true);
        println("Applied " + applied + " symbols (" + failed + " failed) from Vivisect");
        return result;
    }

    // ─── UI feature methods ───

    @SuppressWarnings("unchecked")
    private Map<String, Object> setComment(Map<String, Object> params) {
        String addrStr = getString(params, "address", "");
        String comment = getString(params, "comment", "");
        Map<String, Object> result = new LinkedHashMap<>();
        if (addrStr.isEmpty()) {
            result.put("success", false);
            result.put("error", "Missing address");
            return result;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
            if (addr == null) {
                result.put("success", false);
                result.put("error", "Invalid address: " + addrStr);
                return result;
            }
            currentProgram.getListing().setComment(addr, CodeUnit.EOL_COMMENT, comment);
            result.put("success", true);
            println("Set comment at " + addrStr + ": " + (comment.length() > 50 ? comment.substring(0, 50) + "..." : comment));
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> renameSymbol(Map<String, Object> params) {
        String addrStr = getString(params, "address", "");
        String name = getString(params, "name", "");
        boolean isFunction = getBool(params, "is_function", true);
        Map<String, Object> result = new LinkedHashMap<>();
        if (addrStr.isEmpty() || name.isEmpty()) {
            result.put("success", false);
            result.put("error", "Missing address or name");
            return result;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
            if (addr == null) {
                result.put("success", false);
                result.put("error", "Invalid address: " + addrStr);
                return result;
            }
            if (isFunction) {
                Function func = currentProgram.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    result.put("success", false);
                    result.put("error", "No function at " + addrStr);
                    return result;
                }
                func.setName(name, SourceType.USER_DEFINED);
            } else {
                Symbol[] syms = currentProgram.getSymbolTable().getSymbols(addr);
                if (syms != null && syms.length > 0) {
                    syms[0].setName(name, SourceType.USER_DEFINED);
                } else {
                    currentProgram.getSymbolTable().createLabel(addr, name, SourceType.USER_DEFINED);
                }
            }
            result.put("success", true);
            println("Renamed " + addrStr + " to '" + name + "'");
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> setSignature(Map<String, Object> params) {
        String addrStr = getString(params, "address", "");
        String name = getString(params, "name", "");
        String returnType = getString(params, "return_type", "void");
        List<Object> paramTypesRaw = (List<Object>) params.getOrDefault("param_types", new ArrayList<>());
        String callingConv = getString(params, "calling_conv", "cdecl");
        Map<String, Object> result = new LinkedHashMap<>();
        if (addrStr.isEmpty()) {
            result.put("success", false);
            result.put("error", "Missing address");
            return result;
        }
        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
            if (addr == null) {
                result.put("success", false);
                result.put("error", "Invalid address: " + addrStr);
                return result;
            }
            Function func = currentProgram.getFunctionManager().getFunctionAt(addr);
            if (func == null) {
                func = currentProgram.getFunctionManager().getFunctionContaining(addr);
                if (func == null) {
                    result.put("success", false);
                    result.put("error", "No function at " + addrStr);
                    return result;
                }
            }
            // Rename
            if (!name.isEmpty()) {
                try { func.setName(name, SourceType.USER_DEFINED); } catch (Exception e) { /* best-effort */ }
            }
            // Set return type
            if (!returnType.isEmpty() && !returnType.equals("void")) {
                DataType rt = parseDataType(returnType);
                if (rt != null) {
                    try { func.setReturnType(rt, SourceType.USER_DEFINED); } catch (Exception e) { /* best-effort */ }
                }
            }
            // Set parameters
            if (!paramTypesRaw.isEmpty()) {
                List<Parameter> paramsList = new ArrayList<>();
                for (int i = 0; i < paramTypesRaw.size(); i++) {
                    String ptStr = paramTypesRaw.get(i).toString();
                    DataType pt = parseDataType(ptStr);
                    if (pt != null) {
                        paramsList.add(new ParameterImpl("param" + i, pt, currentProgram));
                    }
                }
                if (!paramsList.isEmpty()) {
                    func.replaceParameters(paramsList,
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        true, SourceType.USER_DEFINED);
                }
            }
            result.put("success", true);
            println("Signature applied to " + addrStr + ": " + name);
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        return result;
    }

    private DataType parseDataType(String typeStr) {
        if (typeStr == null || typeStr.isEmpty()) return null;
        DataTypeManager dtMgr = currentProgram.getDataTypeManager();
        String t = typeStr.trim();
        switch (t) {
            case "int": return dtMgr.getDataType("/int");
            case "unsigned int": return dtMgr.getDataType("/uint");
            case "char": return dtMgr.getDataType("/char");
            case "long": return dtMgr.getDataType("/long");
            case "short": return dtMgr.getDataType("/short");
            case "void": return null;
        }
        if (t.endsWith("*")) {
            String base = t.substring(0, t.length()-1).trim();
            DataType baseDt = parseDataType(base);
            if (baseDt != null) return new PointerDataType(baseDt, dtMgr);
            return new PointerDataType(dtMgr);
        }
        DataType dt = dtMgr.getDataType("/" + t);
        return dt;
    }

    // ─── Decompilation ───

    private Map<String, Object> decompileFunction(Map<String, Object> params) {
        String addrStr = getString(params, "address", "");
        String mode = getString(params, "mode", "standard");
        Map<String, Object> result = new LinkedHashMap<>();

        if (addrStr.isEmpty()) {
            result.put("success", false);
            result.put("error", "Missing address");
            return result;
        }

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
            if (addr == null) {
                result.put("success", false);
                result.put("error", "Invalid address: " + addrStr);
                return result;
            }

            Function function = currentProgram.getFunctionManager().getFunctionAt(addr);
            if (function == null) {
                function = currentProgram.getFunctionManager().getFunctionContaining(addr);
                if (function == null) {
                    result.put("success", false);
                    result.put("error", "No function at " + addrStr);
                    return result;
                }
            }

            // If enriched mode, apply symbols first
            if (mode.equals("enriched") || mode.equals("injected")) {
                List<Object> symbols = (List<Object>) params.getOrDefault("symbols", new ArrayList<>());
                if (!symbols.isEmpty()) {
                    applySymbols(Map.of("symbols", symbols));
                }
            }

            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(currentProgram);
            DecompileResults decompResult = decomp.decompileFunction(function, 60, monitor);

            if (decompResult != null && decompResult.decompileCompleted()) {
                DecompiledFunction df = decompResult.getDecompiledFunction();
                if (df != null) {
                    result.put("success", true);
                    result.put("c_code", df.getC());
                    result.put("function_name", function.getName());
                    result.put("high_pcode", new ArrayList<>());
                    decomp.closeProgram();
                    return result;
                }
            }
            decomp.closeProgram();
            result.put("success", false);
            result.put("error", "Decompilation failed");
            return result;
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", "Error: " + e.getMessage());
            return result;
        }
    }

    // ─── JSON (self-contained) ───

    private Map<String, Object> parseJson(String s) {
        JParser p = new JParser(s);
        Object result = p.parseValue();
        @SuppressWarnings("unchecked")
        Map<String, Object> map = (Map<String, Object>) result;
        return map;
    }

    private String getString(Map<String, Object> m, String k, String def) {
        Object v = m.get(k); return v != null ? v.toString() : def;
    }
    private int getInt(Map<String, Object> m, String k, int def) {
        Object v = m.get(k); if (v instanceof Number) return ((Number)v).intValue(); return def;
    }
    private boolean getBool(Map<String, Object> m, String k, boolean def) {
        Object v = m.get(k); if (v instanceof Boolean) return (Boolean)v; return def;
    }
    @SuppressWarnings("unchecked")
    private Map<String, Object> getMap(Map<String, Object> m, String k) {
        Object v = m.getOrDefault(k, new LinkedHashMap<>());
        if (v instanceof Map) return (Map<String, Object>) v;
        return new LinkedHashMap<>();
    }

    private String stringify(Object obj) {
        StringBuilder sb = new StringBuilder(); writeValue(sb, obj); return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private void writeValue(StringBuilder sb, Object obj) {
        if (obj == null) { sb.append("null"); return; }
        if (obj instanceof String) {
            sb.append('"');
            String str = (String) obj;
            for (int i = 0; i < str.length(); i++) {
                char c = str.charAt(i);
                switch (c) {
                    case '"': sb.append("\\\""); break;
                    case '\\': sb.append("\\\\"); break;
                    case '\n': sb.append("\\n"); break;
                    case '\t': sb.append("\\t"); break;
                    default: sb.append(c);
                }
            }
            sb.append('"'); return;
        }
        if (obj instanceof Boolean || obj instanceof Number) { sb.append(obj); return; }
        if (obj instanceof Map) {
            sb.append('{'); boolean first = true;
            for (Map.Entry<String, Object> e : ((Map<String, Object>) obj).entrySet()) {
                if (!first) sb.append(','); first = false;
                sb.append('"').append(e.getKey()).append('"').append(':');
                writeValue(sb, e.getValue());
            }
            sb.append('}'); return;
        }
        if (obj instanceof List) {
            sb.append('['); boolean first = true;
            for (Object item : (List<Object>) obj) {
                if (!first) sb.append(','); first = false;
                writeValue(sb, item);
            }
            sb.append(']'); return;
        }
        sb.append('"').append(obj).append('"');
    }

    private void sendResponse(BufferedWriter writer, int id, Object result, String error) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("id", id);
        if (error != null) response.put("error", error);
        else response.put("result", result != null ? result : new LinkedHashMap<>());
        try {
            writer.write(stringify(response)); writer.write("\n"); writer.flush();
        } catch (IOException e) { }
    }

    private static class JParser {
        private final String s; private int pos;
        JParser(String s) { this.s = s; this.pos = 0; }
        Object parseValue() {
            skipWs(); char c = s.charAt(pos);
            if (c == '{') return parseObj();
            if (c == '[') return parseArr();
            if (c == '"') return parseStr();
            if (c == 't' || c == 'f') return parseBool();
            if (c == 'n') { pos += 4; return null; }
            return parseNum();
        }
        Map<String, Object> parseObj() {
            Map<String, Object> m = new LinkedHashMap<>();
            pos++; skipWs();
            if (s.charAt(pos) == '}') { pos++; return m; }
            while (true) {
                skipWs(); String k = parseStr(); skipWs(); pos++;
                Object v = parseValue(); m.put(k, v); skipWs();
                char c = s.charAt(pos++);
                if (c == ',') continue; if (c == '}') break;
            }
            return m;
        }
        List<Object> parseArr() {
            List<Object> l = new ArrayList<>();
            pos++; skipWs();
            if (s.charAt(pos) == ']') { pos++; return l; }
            while (true) {
                l.add(parseValue()); skipWs();
                char c = s.charAt(pos++);
                if (c == ',') continue; if (c == ']') break;
            }
            return l;
        }
        String parseStr() {
            pos++; StringBuilder sb = new StringBuilder();
            while (true) {
                char c = s.charAt(pos++);
                if (c == '"') return sb.toString();
                if (c == '\\') {
                    char e = s.charAt(pos++);
                    switch (e) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case 'n': sb.append('\n'); break;
                        case 't': sb.append('\t'); break;
                        default: sb.append(e);
                    }
                } else sb.append(c);
            }
        }
        Object parseNum() {
            int start = pos;
            if (s.charAt(pos) == '-') pos++;
            while (pos < s.length() && (Character.isDigit(s.charAt(pos)) ||
                    s.charAt(pos) == '.' || s.charAt(pos) == 'e' || s.charAt(pos) == 'E')) pos++;
            String n = s.substring(start, pos);
            if (n.contains(".") || n.contains("e") || n.contains("E"))
                return Double.parseDouble(n);
            long l = Long.parseLong(n);
            if (l >= Integer.MIN_VALUE && l <= Integer.MAX_VALUE) return (int) l;
            return l;
        }
        Boolean parseBool() {
            if (s.startsWith("true", pos)) { pos += 4; return true; }
            pos += 5; return false;
        }
        void skipWs() { while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) pos++; }
    }
}