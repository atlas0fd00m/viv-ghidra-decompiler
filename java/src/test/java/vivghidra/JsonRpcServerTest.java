package vivghidra;

import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.net.*;
import java.util.*;

/**
 * Unit tests for JsonRpcServer — the TCP JSON-RPC server.
 *
 * These tests don't require Ghidra — they use a mock RequestHandler
 * and connect directly to the server over loopback.
 */
class JsonRpcServerTest {

    private JsonRpcServer server;
    private Socket client;
    private BufferedReader reader;
    private BufferedWriter writer;
    private int port;

    @BeforeEach
    void setUp() throws Exception {
        // Start server on a random port with a mock handler
        server = new JsonRpcServer(0, new MockHandler());
        server.start();
        port = server.getActualPort();
        Thread.sleep(100); // give server time to bind

        // Connect a client
        client = new Socket("127.0.0.1", port);
        reader = new BufferedReader(new InputStreamReader(client.getInputStream()));
        writer = new BufferedWriter(new OutputStreamWriter(client.getOutputStream()));
    }

    @AfterEach
    void tearDown() throws Exception {
        if (client != null) client.close();
        if (server != null) server.stop();
    }

    @Test
    @DisplayName("Ping returns pong")
    void testPing() throws Exception {
        sendRequest(1, "ping", new LinkedHashMap<>());
        Map<String, Object> response = readResponse();
        assertEquals(1, response.get("id"));
        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) response.get("result");
        assertEquals(true, result.get("pong"));
        assertEquals("1.0", result.get("version"));
    }

    @Test
    @DisplayName("Get status returns program info")
    void testGetStatus() throws Exception {
        sendRequest(2, "get_status", new LinkedHashMap<>());
        Map<String, Object> response = readResponse();
        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) response.get("result");
        assertEquals(true, result.get("program_loaded"));
        assertEquals("test_binary", result.get("program_name"));
    }

    @Test
    @DisplayName("Unknown method returns error")
    void testUnknownMethod() throws Exception {
        sendRequest(3, "nonexistent", new LinkedHashMap<>());
        Map<String, Object> response = readResponse();
        assertEquals(3, response.get("id"));
        assertNotNull(response.get("error"));
        assertTrue(response.get("error").toString().contains("Unknown method"));
    }

    @Test
    @DisplayName("Decompile function with address")
    void testDecompileFunction() throws Exception {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("address", "0x401000");
        params.put("mode", "standard");
        sendRequest(4, "decompile_function", params);

        Map<String, Object> response = readResponse();
        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) response.get("result");
        assertEquals(true, result.get("success"));
        assertNotNull(result.get("c_code"));
    }

    @Test
    @DisplayName("Get function list")
    void testGetFunctionList() throws Exception {
        sendRequest(5, "get_function_list", new LinkedHashMap<>());
        Map<String, Object> response = readResponse();
        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) response.get("result");
        assertNotNull(result.get("functions"));
    }

    @Test
    @DisplayName("Multiple sequential requests")
    void testMultipleRequests() throws Exception {
        for (int i = 0; i < 5; i++) {
            sendRequest(i, "ping", new LinkedHashMap<>());
            Map<String, Object> response = readResponse();
            assertEquals(i, response.get("id"));
        }
    }

    // ─── Helpers ───

    private void sendRequest(int id, String method, Map<String, Object> params) throws Exception {
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("id", id);
        request.put("method", method);
        request.put("params", params);
        writer.write(JsonUtil.stringify(request));
        writer.write("\n");
        writer.flush();
    }

    private Map<String, Object> readResponse() throws Exception {
        String line = reader.readLine();
        assertNotNull(line, "No response from server");
        return JsonUtil.parse(line);
    }

    // ─── Mock Request Handler ───

    static class MockHandler implements JsonRpcServer.RequestHandler {
        @Override
        public Object handle(String method, Map<String, Object> params) throws Exception {
            switch (method) {
                case "ping":
                    Map<String, Object> pingResult = new LinkedHashMap<>();
                    pingResult.put("pong", true);
                    pingResult.put("version", "1.0");
                    return pingResult;

                case "get_status":
                    Map<String, Object> statusResult = new LinkedHashMap<>();
                    statusResult.put("program_loaded", true);
                    statusResult.put("program_name", "test_binary");
                    return statusResult;

                case "decompile_function":
                    Map<String, Object> decompResult = new LinkedHashMap<>();
                    decompResult.put("success", true);
                    decompResult.put("c_code", "int main() { return 0; }");
                    decompResult.put("function_name", "main");
                    return decompResult;

                case "get_function_list":
                    Map<String, Object> funcResult = new LinkedHashMap<>();
                    funcResult.put("functions", Arrays.asList(
                        Map.of("name", "main", "address", "0x401000")
                    ));
                    return funcResult;

                default:
                    throw new IllegalArgumentException("Unknown method: " + method);
            }
        }
    }
}