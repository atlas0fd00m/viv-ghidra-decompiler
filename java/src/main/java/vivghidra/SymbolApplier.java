package vivghidra;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * Applies Vivisect-derived symbol names, function signatures, and data types
 * to the Ghidra Program before decompilation (Mode 1 — symbol enrichment).
 *
 * This is what makes the decompilation "enriched" — Vivisect's analysis often
 * recovers better symbol names and types than Ghidra's auto-analysis, and
 * applying them produces cleaner decompiled output.
 */
public class SymbolApplier {

    private final Program program;

    public SymbolApplier(Program program) {
        this.program = program;
    }

    /**
     * Apply a list of symbol info dictionaries to the program.
     *
     * @param symbols list of maps with keys: name, address, type_name, size,
     *                is_function, is_import, param_types, return_type
     * @return number of symbols successfully applied
     */
    public int applySymbols(List<Object> symbols) {
        int applied = 0;
        for (Object obj : symbols) {
            if (!(obj instanceof Map)) continue;
            @SuppressWarnings("unchecked")
            Map<String, Object> sym = (Map<String, Object>) obj;
            try {
                if (applyOneSymbol(sym)) {
                    applied++;
                }
            } catch (Exception e) {
                // Best-effort — continue on error
            }
        }
        return applied;
    }

    /**
     * Apply a single symbol to the program.
     */
    private boolean applyOneSymbol(Map<String, Object> sym) {
        String name = JsonUtil.getString(sym, "name", "");
        String addrStr = JsonUtil.getString(sym, "address", "0x0");
        boolean isFunction = JsonUtil.getBool(sym, "is_function", false);
        boolean isImport = JsonUtil.getBool(sym, "is_import", false);

        if (name.isEmpty()) return false;

        AddressFactory addrFactory = program.getAddressFactory();
        Address address;
        try {
            address = addrFactory.getAddress(addrStr);
        } catch (Exception e) {
            return false;
        }
        if (address == null) return false;

        if (isFunction) {
            return applyFunctionSymbol(address, name, sym);
        } else {
            return applyDataSymbol(address, name, sym);
        }
    }

    /**
     * Apply a function name and optionally a signature to the program.
     */
    private boolean applyFunctionSymbol(Address address, String name, Map<String, Object> sym) {
        FunctionManager funcMgr = program.getFunctionManager();
        Function function = funcMgr.getFunctionAt(address);

        if (function == null) {
            // Function doesn't exist in Ghidra — create it
            try {
                function = funcMgr.createFunction(name, address, null,
                    ghidra.program.model.symbol.SourceType.USER_DEFINED);
            } catch (Exception e) {
                return false;
            }
            if (function == null) return false;
        } else {
            // Rename the function
            try {
                function.setName(name, ghidra.program.model.symbol.SourceType.USER_DEFINED);
            } catch (Exception e) {
                // Name might conflict — try with suffix
                try {
                    function.setName(name + "_viv", ghidra.program.model.symbol.SourceType.USER_DEFINED);
                } catch (Exception e2) {
                    return false;
                }
            }
        }

        // Apply return type if specified
        String returnType = JsonUtil.getString(sym, "return_type", "");
        if (!returnType.isEmpty() && !returnType.equals("void")) {
            try {
                DataType returnTypeDt = parseDataType(returnType);
                if (returnTypeDt != null) {
                    function.setReturnType(returnTypeDt, ghidra.program.model.symbol.SourceType.USER_DEFINED);
                }
            } catch (Exception e) { /* best-effort */ }
        }

        // Apply parameter types if specified
        @SuppressWarnings("unchecked")
        List<Object> paramTypes = (List<Object>) sym.getOrDefault("param_types", new ArrayList<>());
        if (!paramTypes.isEmpty()) {
            try {
                java.util.List<Parameter> params = new ArrayList<>();
                for (int i = 0; i < paramTypes.size(); i++) {
                    String paramTypeStr = paramTypes.get(i).toString();
                    String paramName = "param" + i;
                    DataType paramType = parseDataType(paramTypeStr);
                    if (paramType != null) {
                        params.add(new ParameterImpl(paramName, paramType, program));
                    }
                }
                if (!params.isEmpty()) {
                    function.replaceParameters(params,
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        true, ghidra.program.model.symbol.SourceType.USER_DEFINED);
                }
            } catch (Exception e) { /* best-effort */ }
        }

        return true;
    }

    /**
     * Apply a data symbol (variable name, type) to the program.
     */
    private boolean applyDataSymbol(Address address, String name, Map<String, Object> sym) {
        SymbolTable symTable = program.getSymbolTable();

        // Check if a symbol already exists at this address
        Symbol[] existing = symTable.getSymbols(address);
        if (existing != null && existing.length > 0) {
            // Rename the primary symbol
            try {
                existing[0].setName(name, ghidra.program.model.symbol.SourceType.USER_DEFINED);
                return true;
            } catch (Exception e) {
                return false;
            }
        }

        // Create a new label
        try {
            symTable.createLabel(address, name, ghidra.program.model.symbol.SourceType.USER_DEFINED);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Parse a C type string into a Ghidra DataType.
     * This is intentionally simple — handles common types.
     */
    private DataType parseDataType(String typeStr) {
        if (typeStr == null || typeStr.isEmpty()) return null;

        DataTypeManager dtMgr = program.getDataTypeManager();
        String trimmed = typeStr.trim();

        // Handle common built-in types
        switch (trimmed) {
            case "int": return dtMgr.getDataType("/int");
            case "unsigned int": return dtMgr.getDataType("/uint");
            case "char": return dtMgr.getDataType("/char");
            case "void": return null; // void needs no data type
            case "long": return dtMgr.getDataType("/long");
            case "short": return dtMgr.getDataType("/short");
            case "float": return dtMgr.getDataType("/float");
            case "double": dtMgr.getDataType("/double");
            case "size_t": return dtMgr.getDataType("/size_t");
        }

        // Handle pointer types (ending with *)
        if (trimmed.endsWith("*")) {
            String base = trimmed.substring(0, trimmed.length() - 1).trim();
            DataType baseType = parseDataType(base);
            if (baseType != null) {
                return new PointerDataType(baseType, dtMgr);
            }
            // Generic pointer
            return new PointerDataType(dtMgr);
        }

        // Try to find in the data type manager by path
        DataType dt = dtMgr.getDataType("/" + trimmed);
        if (dt != null) return dt;

        // Fallback: try as undefined
        return null;
    }

    // ─── UI feature methods ───

    /**
     * Set an end-of-line comment at a specific address in the program.
     *
     * @param addrStr hex address string (e.g., "0x401156")
     * @param comment comment text
     * @return true if comment was set successfully
     */
    public boolean setComment(String addrStr, String comment) {
        AddressFactory addrFactory = program.getAddressFactory();
        Address address;
        try {
            address = addrFactory.getAddress(addrStr);
        } catch (Exception e) {
            return false;
        }
        if (address == null) return false;

        try {
            program.getListing().setComment(address, CodeUnit.EOL_COMMENT, comment);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Rename a symbol (function or data) at a specific address.
     *
     * @param addrStr hex address string
     * @param name new name
     * @param isFunction true if renaming a function, false for data
     * @return true if rename succeeded
     */
    public boolean renameSymbol(String addrStr, String name, boolean isFunction) {
        if (name == null || name.isEmpty()) return false;

        AddressFactory addrFactory = program.getAddressFactory();
        Address address;
        try {
            address = addrFactory.getAddress(addrStr);
        } catch (Exception e) {
            return false;
        }
        if (address == null) return false;

        if (isFunction) {
            FunctionManager funcMgr = program.getFunctionManager();
            Function function = funcMgr.getFunctionAt(address);
            if (function == null) return false;
            try {
                function.setName(name, ghidra.program.model.symbol.SourceType.USER_DEFINED);
                return true;
            } catch (Exception e) {
                return false;
            }
        } else {
            SymbolTable symTable = program.getSymbolTable();
            Symbol[] existing = symTable.getSymbols(address);
            if (existing != null && existing.length > 0) {
                try {
                    existing[0].setName(name, ghidra.program.model.symbol.SourceType.USER_DEFINED);
                    return true;
                } catch (Exception e) {
                    return false;
                }
            }
            try {
                symTable.createLabel(address, name, ghidra.program.model.symbol.SourceType.USER_DEFINED);
                return true;
            } catch (Exception e) {
                return false;
            }
        }
    }

    /**
     * Set a full function signature (name, return type, parameters, calling convention).
     *
     * @param addrStr hex address string
     * @param name function name
     * @param returnTypeStr C return type string
     * @param paramTypeStrs list of C type strings for parameters
     * @param callingConv calling convention (e.g., "cdecl", "stdcall")
     * @return true if signature was applied successfully
     */
    public boolean setSignature(String addrStr, String name, String returnTypeStr,
                                 List<String> paramTypeStrs, String callingConv) {
        AddressFactory addrFactory = program.getAddressFactory();
        Address address;
        try {
            address = addrFactory.getAddress(addrStr);
        } catch (Exception e) {
            return false;
        }
        if (address == null) return false;

        FunctionManager funcMgr = program.getFunctionManager();
        Function function = funcMgr.getFunctionAt(address);
        if (function == null) {
            // Try to find containing function
            function = funcMgr.getFunctionContaining(address);
            if (function == null) return false;
        }

        // Rename
        if (name != null && !name.isEmpty()) {
            try {
                function.setName(name, ghidra.program.model.symbol.SourceType.USER_DEFINED);
            } catch (Exception e) {
                // best-effort
            }
        }

        // Set return type
        if (returnTypeStr != null && !returnTypeStr.isEmpty() && !returnTypeStr.equals("void")) {
            try {
                DataType returnType = parseDataType(returnTypeStr);
                if (returnType != null) {
                    function.setReturnType(returnType, ghidra.program.model.symbol.SourceType.USER_DEFINED);
                }
            } catch (Exception e) { /* best-effort */ }
        }

        // Set parameters
        if (paramTypeStrs != null && !paramTypeStrs.isEmpty()) {
            try {
                java.util.List<Parameter> params = new ArrayList<>();
                for (int i = 0; i < paramTypeStrs.size(); i++) {
                    String paramTypeStr = paramTypeStrs.get(i);
                    String paramName = "param" + i;
                    DataType paramType = parseDataType(paramTypeStr);
                    if (paramType != null) {
                        params.add(new ParameterImpl(paramName, paramType, program));
                    }
                }
                if (!params.isEmpty()) {
                    function.replaceParameters(params,
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        true, ghidra.program.model.symbol.SourceType.USER_DEFINED);
                }
            } catch (Exception e) { /* best-effort */ }
        }

        return true;
    }
}