package vivghidra;

import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * Wraps Ghidra's DecompInterface to provide programmatic decompilation.
 *
 * This is the core of the Ghidra side: it takes a function address,
 * optionally applies Vivisect-derived symbol information, then decompiles
 * using Ghidra's decompiler engine.
 */
public class DecompilerService {

    private DecompInterface decompInterface;
    private Program program;
    private int timeoutSecs = 60;
    private boolean initialized = false;

    /**
     * Initialize the decompiler for the given program.
     */
    public synchronized void openProgram(Program program) {
        closeProgram();
        this.program = program;
        decompInterface = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decompInterface.setOptions(options);
        decompInterface.toggleCCode(true);
        decompInterface.toggleSyntaxTree(true);
        decompInterface.setSimplificationStyle("decompile");
        decompInterface.openProgram(program);
        initialized = true;
    }

    /**
     * Release the current program.
     */
    public synchronized void closeProgram() {
        if (decompInterface != null) {
            decompInterface.closeProgram();
            decompInterface.dispose();
            decompInterface = null;
        }
        program = null;
        initialized = false;
    }

    /**
     * Decompile a function at the given address.
     *
     * @param address the function entry point address
     * @return a DecompileResult containing C pseudocode
     */
    public synchronized DecompileResult decompile(Address address) {
        if (!initialized || program == null) {
            return DecompileResult.error("Decompiler not initialized");
        }

        FunctionManager funcMgr = program.getFunctionManager();
        Function function = funcMgr.getFunctionAt(address);
        if (function == null) {
            // Try to find a function containing this address
            function = funcMgr.getFunctionContaining(address);
            if (function == null) {
                return DecompileResult.error("No function at address: " + address);
            }
        }

        try {
            DecompileResults results = decompInterface.decompileFunction(
                function, timeoutSecs, TaskMonitor.DUMMY);

            if (results == null) {
                return DecompileResult.error("Decompiler returned null results");
            }
            if (!results.decompileCompleted()) {
                return DecompileResult.error("Decompilation failed: " + results.getErrorMessage());
            }

            DecompiledFunction decompFunc = results.getDecompiledFunction();
            if (decompFunc == null) {
                return DecompileResult.error("Decompiled function is null");
            }

            String cCode = decompFunc.getC();
            String funcName = function.getName();

            // Extract high p-code if available
            List<Map<String, Object>> highPcode = new ArrayList<>();
            try {
                HighFunction hf = results.getHighFunction();
                if (hf != null) {
                    // Could iterate over hf.getPcodeOps() and serialize them
                    // For now, just note that high p-code is available
                    highPcode.add(Map.of("available", true, "op_count", "see_high_function"));
                }
            } catch (Exception e) {
                // High p-code extraction is best-effort
            }

            return DecompileResult.success(cCode, funcName, highPcode);

        } catch (Exception e) {
            return DecompileResult.error("Decompilation error: " + e.getMessage());
        }
    }

    /**
     * Decompile a function at the given address string.
     */
    public DecompileResult decompile(String addressStr) {
        if (!initialized || program == null) {
            return DecompileResult.error("Decompiler not initialized");
        }
        try {
            AddressFactory addrFactory = program.getAddressFactory();
            Address address = addrFactory.getAddress(addressStr);
            if (address == null) {
                return DecompileResult.error("Invalid address: " + addressStr);
            }
            return decompile(address);
        } catch (Exception e) {
            return DecompileResult.error("Address parse error: " + e.getMessage());
        }
    }

    /**
     * Get a list of all functions in the program.
     */
    public List<Map<String, Object>> getFunctionList() {
        if (!initialized || program == null) {
            return new ArrayList<>();
        }

        List<Map<String, Object>> functions = new ArrayList<>();
        FunctionManager funcMgr = program.getFunctionManager();
        FunctionIterator iter = funcMgr.getFunctions(true);
        while (iter.hasNext()) {
            Function f = iter.next();
            Map<String, Object> info = new LinkedHashMap<>();
            info.put("name", f.getName());
            info.put("address", f.getEntryPoint().toString());
            info.put("size", f.getBody().getNumAddresses());
            functions.add(info);
        }
        return functions;
    }

    /**
     * Get the current program name.
     */
    public String getProgramName() {
        if (program == null) return "";
        return program.getName();
    }

    /**
     * Check if a program is loaded.
     */
    public boolean isProgramLoaded() {
        return program != null && initialized;
    }

    /**
     * Set the decompiler timeout in seconds.
     */
    public void setTimeout(int secs) {
        this.timeoutSecs = secs;
    }

    // ─── Result class ───

    public static class DecompileResult {
        public final boolean success;
        public final String cCode;
        public final String functionName;
        public final String error;
        public final List<Map<String, Object>> highPcode;

        private DecompileResult(boolean success, String cCode, String funcName,
                                  String error, List<Map<String, Object>> highPcode) {
            this.success = success;
            this.cCode = cCode;
            this.functionName = funcName;
            this.error = error;
            this.highPcode = highPcode;
        }

        public static DecompileResult success(String cCode, String funcName,
                                                List<Map<String, Object>> highPcode) {
            return new DecompileResult(true, cCode, funcName, null,
                highPcode != null ? highPcode : new ArrayList<>());
        }

        public static DecompileResult error(String error) {
            return new DecompileResult(false, null, null, error, new ArrayList<>());
        }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("success", success);
            if (success) {
                map.put("c_code", cCode != null ? cCode : "");
                map.put("function_name", functionName != null ? functionName : "");
                map.put("high_pcode", highPcode);
            } else {
                map.put("error", error != null ? error : "Unknown error");
            }
            return map;
        }
    }
}