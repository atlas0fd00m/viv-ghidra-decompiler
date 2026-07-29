package vivghidra;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;

/**
 * TCP server that speaks the newline-delimited JSON-RPC protocol.
 *
 * Runs as a daemon thread. One worker thread per client connection.
 * Dispatches requests to the registered RequestHandler.
 *
 * Zero external dependencies — uses JsonUtil for all JSON parsing/serialization.
 */
public class JsonRpcServer {

    private final int port;
    private final RequestHandler handler;
    private ServerSocket serverSocket;
    private Thread serverThread;
    private volatile boolean running;
    private final List<Thread> clientThreads = new CopyOnWriteArrayList<>();

    /**
     * Interface for handling JSON-RPC requests.
     */
    public interface RequestHandler {
        /**
         * Handle a single JSON-RPC request.
         * @param method the method name
         * @param params the parameters (may be empty map)
         * @return the result object (will be JSON-serialized)
         * @throws Exception on error — the exception message becomes the error response
         */
        Object handle(String method, Map<String, Object> params) throws Exception;
    }

    public JsonRpcServer(int port, RequestHandler handler) {
        this.port = port;
        this.handler = handler;
    }

    /**
     * Start the TCP server on the configured port.
     */
    public void start() throws IOException {
        serverSocket = new ServerSocket(port);
        running = true;
        serverThread = new Thread(this::serveLoop, "VivGhidra-Server");
        serverThread.setDaemon(true);
        serverThread.start();
    }

    /**
     * Stop the TCP server and close all connections.
     */
    public void stop() {
        running = false;
        if (serverSocket != null) {
            try { serverSocket.close(); } catch (IOException e) { /* ignore */ }
        }
        for (Thread t : clientThreads) {
            t.interrupt();
        }
        clientThreads.clear();
    }

    /**
     * Get the actual port the server is listening on.
     * Useful when port 0 is specified (OS assigns a free port).
     */
    public int getActualPort() {
        if (serverSocket != null && serverSocket.isBound()) {
            return serverSocket.getLocalPort();
        }
        return port;
    }

    public boolean isRunning() {
        return running;
    }

    private void serveLoop() {
        while (running) {
            try {
                Socket client = serverSocket.accept();
                Thread t = new Thread(() -> handleClient(client), "VivGhidra-Client");
                t.setDaemon(true);
                clientThreads.add(t);
                t.start();
            } catch (IOException e) {
                if (running) {
                    // Log and continue
                    System.err.println("[VivGhidra] Accept error: " + e.getMessage());
                }
                break;
            }
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
                        Object result = handler.handle(method, params);
                        sendResponse(writer, id, result, null);
                    } catch (Exception e) {
                        sendResponse(writer, id, null, e.getMessage());
                    }
                } catch (Exception e) {
                    // Bad JSON — send error response with id 0
                    sendResponse(writer, 0, null, "Parse error: " + e.getMessage());
                }
            }
        } catch (IOException e) {
            // Client disconnected — normal
        } finally {
            clientThreads.remove(Thread.currentThread());
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
        } catch (IOException e) {
            // Client gone — can't send
        }
    }
}