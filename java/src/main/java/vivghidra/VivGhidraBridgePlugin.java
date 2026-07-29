package vivghidra;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;

import java.util.*;

/**
 * Vivisect-Ghidra Symbolik Decompiler Bridge Plugin.
 *
 * This plugin runs a JSON-RPC TCP server inside Ghidra, allowing the
 * Vivisect extension to request decompilation of functions. It wraps
 * Ghidra's DecompInterface and optionally applies Vivisect-derived
 * symbol information before decompilation.
 *
 * Architecture:
 *
 *   Vivisect (Python)                   Ghidra (Java, this plugin)
 *   ┌─────────────────┐                 ┌──────────────────────────┐
 *   │ vivExtension()  │   JSON-RPC      │ VivGhidraBridgePlugin    │
 *   │ GhidraClient    │ ───────────→   │ JsonRpcServer             │
 *   │ PcodeTranslator │   over TCP      │ DecompilerService         │
 *   │ SymbolExtractor  │ ←───────────   │ SymbolApplier             │
 *   └─────────────────┘   C pseudocode  │ PcodeInjector             │
 *                                        └──────────────────────────┘
 *
 * Protocol: newline-delimited JSON over TCP.
 * Default port: 13100 (configurable via VIVGHIDRA_PORT env var).
 */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = CorePluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Vivisect-Ghidra decompiler bridge",
    description = "Exposes Ghidra's decompiler to Vivisect via JSON-RPC over TCP. " +
                  "Receives symbol-enriched decompilation requests from the Vivisect " +
                  "extension and returns C pseudocode."
)
public class VivGhidraBridgePlugin extends ProgramPlugin implements JsonRpcServer.RequestHandler {

    private DecompilerService decompilerService;
    private SymbolApplier symbolApplier;
    private PcodeInjector pcodeInjector;
    private JsonRpcServer rpcServer;
    private int serverPort = Protocol.DEFAULT_PORT;

    public VivGhidraBridgePlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    protected void programActivated(Program program) {
        // Initialize services for the new program
        decompilerService = new DecompilerService();
        decompilerService.openProgram(program);
        symbolApplier = new SymbolApplier(program);
        pcodeInjector = new PcodeInjector(program);

        // Start or restart the TCP server
        startRpcServer();

        System.out.println("[VivGhidra] Program activated: " + program.getName() +
            " — server on port " + serverPort);
    }

    @Override
    protected void programDeactivated(Program program) {
        // Stop the server and release the decompiler
        stopRpcServer();
        if (decompilerService != null) {
            decompilerService.closeProgram();
        }
        decompilerService = null;
        symbolApplier = null;
        pcodeInjector = null;

        System.out.println("[VivGhidra] Program deactivated: " + program.getName());
    }

    @Override
    protected void dispose() {
        stopRpcServer();
        if (decompilerService != null) {
            decompilerService.closeProgram();
        }
        super.dispose();
    }

    /**
     * Start the JSON-RPC TCP server.
     * If a server is already running, stop it first.
     */
    private void startRpcServer() {
        stopRpcServer();

        // Check for port override from environment
        String portEnv = System.getenv("VIVGHIDRA_PORT");
        if (portEnv != null && !portEnv.isEmpty()) {
            try { serverPort = Integer.parseInt(portEnv); } catch (Exception e) { /* keep default */ }
        }

        try {
            rpcServer = new JsonRpcServer(serverPort, this);
            rpcServer.start();
            serverPort = rpcServer.getActualPort();
        } catch (Exception e) {
            System.err.println("[VivGhidra] Failed to start TCP server: " + e.getMessage());
        }
    }

    private void stopRpcServer() {
        if (rpcServer != null) {
            rpcServer.stop();
            rpcServer = null;
        }
    }

    // ─── JSON-RPC Request Handler ───

    @Override
    public Object handle(String method, Map<String, Object> params) throws Exception {
        switch (method) {
            case Protocol.PING:
                return handlePing();

            case Protocol.GET_STATUS:
                return handleGetStatus();

            case Protocol.DECOMPILE_FUNCTION:
                return handleDecompileFunction(params);

            case Protocol.GET_PCODE:
                return handleGetPcode(params);

            case Protocol.APPLY_SYMBOLS:
                return handleApplySymbols(params);

            case Protocol.GET_FUNCTION_LIST:
                return handleGetFunctionList();

            case Protocol.SET_DECOMPILER_OPTIONS:
                return handleSetDecompilerOptions(params);

            default:
                throw new IllegalArgumentException("Unknown method: " + method);
        }
    }

    // ─── Protocol method implementations ───

    private Map<String, Object> handlePing() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put(Protocol.RESULT_PONG, true);
        result.put(Protocol.RESULT_VERSION, Protocol.VERSION);
        return result;
    }

    private Map<String, Object> handleGetStatus() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put(Protocol.RESULT_PROGRAM_LOADED, decompilerService != null && decompilerService.isProgramLoaded());
        result.put(Protocol.RESULT_PROGRAM_NAME, decompilerService != null ? decompilerService.getProgramName() : "");
        return result;
    }

    private Map<String, Object> handleDecompileFunction(Map<String, Object> params) {
        String addressStr = JsonUtil.getString(params, Protocol.PARAM_ADDRESS, "");
        String mode = JsonUtil.getString(params, Protocol.PARAM_MODE, Protocol.MODE_STANDARD);

        if (addressStr.isEmpty()) {
            Map<String, Object> err = new LinkedHashMap<>();
            err.put(Protocol.RESULT_SUCCESS, false);
            err.put(Protocol.RESULT_ERROR, "Missing 'address' parameter");
            return err;
        }

        // Mode 1: Apply symbols before decompilation (enriched mode)
        if (mode.equals(Protocol.MODE_ENRICHED) || mode.equals(Protocol.MODE_INJECTED)) {
            List<Object> symbols = JsonUtil.getList(params, Protocol.PARAM_SYMBOLS);
            if (!symbols.isEmpty() && symbolApplier != null) {
                int applied = symbolApplier.applySymbols(symbols);
                System.out.println("[VivGhidra] Applied " + applied + " symbols from Vivisect");
            }
        }

        // Mode 2: Inject p-code (experimental)
        if (mode.equals(Protocol.MODE_INJECTED)) {
            List<Object> pcode = JsonUtil.getList(params, Protocol.PARAM_PCODE);
            if (!pcode.isEmpty() && pcodeInjector != null) {
                boolean injected = pcodeInjector.injectPcode(addressStr, pcode);
                if (injected) {
                    System.out.println("[VivGhidra] P-code injection succeeded for " + addressStr);
                }
                // Falls back to standard decompilation if injection not available
            }
        }

        // Decompile
        if (decompilerService == null) {
            Map<String, Object> err = new LinkedHashMap<>();
            err.put(Protocol.RESULT_SUCCESS, false);
            err.put(Protocol.RESULT_ERROR, "No program loaded");
            return err;
        }

        DecompilerService.DecompileResult result = decompilerService.decompile(addressStr);
        return result.toMap();
    }

    private Map<String, Object> handleGetPcode(Map<String, Object> params) {
        String addressStr = JsonUtil.getString(params, Protocol.PARAM_ADDRESS, "");
        Map<String, Object> result = new LinkedHashMap<>();
        if (pcodeInjector != null && !addressStr.isEmpty()) {
            List<Map<String, Object>> pcode = pcodeInjector.getRawPcode(addressStr);
            result.put("pcode", pcode);
            result.put(Protocol.RESULT_SUCCESS, true);
        } else {
            result.put(Protocol.RESULT_SUCCESS, false);
            result.put(Protocol.RESULT_ERROR, "No program or missing address");
        }
        return result;
    }

    private Map<String, Object> handleApplySymbols(Map<String, Object> params) {
        List<Object> symbols = JsonUtil.getList(params, Protocol.PARAM_SYMBOLS);
        Map<String, Object> result = new LinkedHashMap<>();
        if (symbolApplier != null) {
            int applied = symbolApplier.applySymbols(symbols);
            result.put(Protocol.RESULT_APPLIED, applied);
            result.put(Protocol.RESULT_SUCCESS, true);
        } else {
            result.put(Protocol.RESULT_SUCCESS, false);
            result.put(Protocol.RESULT_ERROR, "No program loaded");
        }
        return result;
    }

    private Map<String, Object> handleGetFunctionList() {
        Map<String, Object> result = new LinkedHashMap<>();
        if (decompilerService != null && decompilerService.isProgramLoaded()) {
            result.put(Protocol.RESULT_FUNCTIONS, decompilerService.getFunctionList());
            result.put(Protocol.RESULT_SUCCESS, true);
        } else {
            result.put(Protocol.RESULT_FUNCTIONS, new ArrayList<>());
            result.put(Protocol.RESULT_SUCCESS, false);
            result.put(Protocol.RESULT_ERROR, "No program loaded");
        }
        return result;
    }

    private Map<String, Object> handleSetDecompilerOptions(Map<String, Object> params) {
        Map<String, Object> result = new LinkedHashMap<>();
        // Could set decompiler options here (simplification style, etc.)
        result.put(Protocol.RESULT_SUCCESS, true);
        return result;
    }
}