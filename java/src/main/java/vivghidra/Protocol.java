package vivghidra;

/**
 * Protocol constants and method names for the Vivisect-Ghidra bridge JSON-RPC protocol.
 *
 * Both the Java server and Python client must agree on these constants.
 */
public class Protocol {
    // Protocol version
    public static final String VERSION = "1.0";

    // Method names
    public static final String PING = "ping";
    public static final String GET_STATUS = "get_status";
    public static final String DECOMPILE_FUNCTION = "decompile_function";
    public static final String GET_PCODE = "get_pcode";
    public static final String APPLY_SYMBOLS = "apply_symbols";
    public static final String GET_FUNCTION_LIST = "get_function_list";
    public static final String SET_DECOMPILER_OPTIONS = "set_decompiler_options";

    // Parameter keys
    public static final String PARAM_ADDRESS = "address";
    public static final String PARAM_MODE = "mode";
    public static final String PARAM_SYMBOLS = "symbols";
    public static final String PARAM_PCODE = "pcode";
    public static final String PARAM_OPTIONS = "options";

    // Result keys
    public static final String RESULT_PONG = "pong";
    public static final String RESULT_VERSION = "version";
    public static final String RESULT_PROGRAM_LOADED = "program_loaded";
    public static final String RESULT_PROGRAM_NAME = "program_name";
    public static final String RESULT_C_CODE = "c_code";
    public static final String RESULT_HIGH_PCODE = "high_pcode";
    public static final String RESULT_FUNCTION_NAME = "function_name";
    public static final String RESULT_SUCCESS = "success";
    public static final String RESULT_ERROR = "error";
    public static final String RESULT_FUNCTIONS = "functions";
    public static final String RESULT_APPLIED = "applied";

    // Decompile modes
    public static final String MODE_STANDARD = "standard";
    public static final String MODE_ENRICHED = "enriched";
    public static final String MODE_INJECTED = "injected";

    // Default port
    public static final int DEFAULT_PORT = 13100;
}