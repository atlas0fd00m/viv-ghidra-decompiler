// Ghidra headless script: Start the Vivisect-Ghidra bridge TCP server.
// This script is run via analyzeHeadless -postScript.
// It imports the binary, runs auto-analysis, then starts the TCP server
// and keeps it alive for incoming decompilation requests.
//
// @category VivGhidra
// @author UberNethers

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.util.task.TaskMonitor;

import vivghidra.JsonUtil;
import vivghidra.Protocol;

import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.util.*;
import java.util.concurrent.*;

public class StartBridgeServer extends GhidraScript {

    private static final int DEFAULT_PORT = 13100;
    private static final int SHUTDOWN_PORT = 13199; // connect to this to shut down
    private ServerSocket serverSocket;
    private ServerSocket shutdownSocket;
    private volatile boolean running = true;
    private ExecutorService pool;
    private Map<String, Object> programInfo;

    @Override
    protected void run() throws Exception {
        int port = DEFAULT_PORT;
        String portEnv = System.getenv("VIVGHIDRA_PORT");
        if (portEnv != null && !portEnv.isEmpty()) {
            try { port = Integer.parseInt(portEnv); } catch (Exception e) { }
        }

        // Collect function info
        List<Map<String, Object>> functions = new ArrayList<>();
        FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
        while (iter.hasNext()) {
            Function f = iter.next();
            Map<String, Object> info = new LinkedHashMap<>();
            info.put("name", f.getName());
            info.put("address", f.getEntryPoint().toString());
            info.put("size", f.getBody().getNumAddresses());
            functions.add(info);
        }
        programInfo = new LinkedHashMap<>();
        programInfo.put("functions", functions);
        programInfo.put("program_name", currentProgram.getName());

        println("=== Vivisect-Ghidra Bridge Server ===");
        println("Program: " + currentProgram.getName());
        println("Functions found: " + functions.size());
        for (Map<String, Object> f : functions) {
            println("  " + f.get("name") + " @ " + f.get("address"));
        }

        // Start TCP server
        serverSocket = new ServerSocket(port);
        shutdownSocket = new ServerSocket(SHUTDOWN_PORT);
        pool = Executors.newCachedThreadPool();

        println("Bridge server listening on port " + port);
        println("Shutdown socket on port " + SHUTDOWN_PORT);
        println("Send a request to port " + SHUTDOWN_PORT + " to shut down.");

        // Accept loop
        while (running) {
            // Check for shutdown
            if (shutdownSocketIsConnected()) {
                running = false;
                break;
            }
            try {
                serverSocket.setSoTimeout(500);
                Socket client = serverSocket.accept();
                pool.submit(() -> handleClient(client));
            } catch (java.net.SocketTimeoutException e) {
                // Normal — loop and check shutdown
            }
        }

        // Cleanup
        println("Shutting down bridge server...");
        pool.shutdownNow();
        serverSocket.close();
        shutdownSocket.close();
        println("Bridge server stopped.");
    }

    private boolean shutdownSocketIsConnected() {
        try {
            shutdownSocket.setSoTimeout(100);
            Socket s = shutdownSocket.accept();
            s.close();
            return true;
        } catch (java.net.SocketTimeoutException e) {
            return false;
        } catch (Exception e) {
            return false;
        }
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
                    Map<String, Object> request = JsonUtil.parse(line);
                    int id = JsonUtil.getInt(request, "id", 0);
                    String method = JsonUtil.getString(request, "method", "");
                    @SuppressWarnings("unchecked")
                    Map<String, Object> params = (Map<String, Object>) request.getOrDefault("params", new LinkedHashMap<>());
                    if (params == null) params = new LinkedHashMap<>();

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
        } catch (IOException e) {
            // Client disconnected
        }
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
            case "decompile_function": {
                return decompileFunction(params);
            }
            case "get_function_list": {
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("functions", programInfo.get("functions"));
                r.put("success", true);
                return r;
            }
            case "apply_symbols": {
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("applied", 0);
                r.put("success", true);
                return r;
            }
            default:
                throw new IllegalArgumentException("Unknown method: " + method);
        }
    }

    private Map<String, Object> decompileFunction(Map<String, Object> params) {
        String addrStr = JsonUtil.getString(params, "address", "");
        Map<String, Object> result = new LinkedHashMap<>();

        if (addrStr.isEmpty()) {
            result.put("success", false);
            result.put("error", "Missing address");
            return result;
        }

        try {
            ghidra.program.model.address.Address addr =
                currentProgram.getAddressFactory().getAddress(addrStr);
            if (addr == null) {
                result.put("success", false);
                result.put("error", "Invalid address: " + addrStr);
                return result;
            }

            ghidra.program.model.listing.Function function =
                currentProgram.getFunctionManager().getFunctionAt(addr);
            if (function == null) {
                function = currentProgram.getFunctionManager().getFunctionContaining(addr);
                if (function == null) {
                    result.put("success", false);
                    result.put("error", "No function at " + addrStr);
                    return result;
                }
            }

            // Use DecompInterface
            ghidra.app.decompiler.DecompInterface decomp = new ghidra.app.decompiler.DecompInterface();
            decomp.openProgram(currentProgram);
            ghidra.app.decompiler.DecompileResults decompResult =
                decomp.decompileFunction(function, 60, monitor);

            if (decompResult != null && decompResult.decompileCompleted()) {
                ghidra.app.decompiler.DecompiledFunction df = decompResult.getDecompiledFunction();
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

    private void sendResponse(BufferedWriter writer, int id, Object result, String error) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("id", id);
        if (error != null) {
            response.put("error", error);
        } else {
            response.put("result", result != null ? result : new LinkedHashMap<>());
        }
        try {
            writer.write(JsonUtil.stringify(response));
            writer.write("\n");
            writer.flush();
        } catch (IOException e) { }
    }
}