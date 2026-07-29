package vivghidra;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.*;

import java.util.*;

/**
 * Injects p-code at specific addresses (Mode 2 — experimental).
 *
 * This is for the case where Vivisect's symbolik translation produces
 * better p-code than Ghidra's Sleigh translation. The injected p-code
 * overrides the instruction-level p-code that Ghidra would normally
 * generate.
 *
 * NOTE: P-code injection for decompilation is experimental. The Ghidra
 * decompiler reads Sleigh-generated p-code, not injected p-code, in
 * standard operation. This class provides the infrastructure but
 * may need to use Ghidra's p-code override mechanisms or fall back
 * to Mode 1 (symbol enrichment).
 */
public class PcodeInjector {

    private final Program program;

    public PcodeInjector(Program program) {
        this.program = program;
    }

    /**
     * Inject p-code ops at a given address.
     *
     * @param addressStr the target address as a string (e.g., "0x401000")
     * @param pcodeOps list of p-code op dictionaries with keys:
     *                 opcode, output (nullable), inputs (list), va, order
     * @return true if injection was set up (may not affect decompiler)
     */
    public boolean injectPcode(String addressStr, List<Object> pcodeOps) {
        if (pcodeOps == null || pcodeOps.isEmpty()) return false;

        AddressFactory addrFactory = program.getAddressFactory();
        Address address;
        try {
            address = addrFactory.getAddress(addressStr);
        } catch (Exception e) {
            return false;
        }
        if (address == null) return false;

        // TODO: Use Ghidra's PcodeOverride or PcodeEmulator.inject() to
        // actually inject p-code at this address. The exact API depends
        // on the Ghidra version and whether we're working with the
        // decompiler or the emulator.
        //
        // For now, this is a placeholder that validates the input and
        // returns false to indicate injection is not yet implemented.
        // Mode 1 (symbol enrichment) is the primary path.

        // Validate p-code ops structure
        for (Object obj : pcodeOps) {
            if (!(obj instanceof Map)) return false;
            @SuppressWarnings("unchecked")
            Map<String, Object> op = (Map<String, Object>) obj;
            if (!op.containsKey("opcode")) return false;
        }

        // Log what we would inject
        System.out.println("[VivGhidra] P-code injection requested at " + addressStr +
            " with " + pcodeOps.size() + " ops (not yet implemented — using Mode 1 fallback)");
        return false;
    }

    /**
     * Get the raw p-code for a function at the given address.
     * This returns Ghidra's own Sleigh-generated p-code.
     */
    public List<Map<String, Object>> getRawPcode(String addressStr) {
        List<Map<String, Object>> result = new ArrayList<>();

        AddressFactory addrFactory = program.getAddressFactory();
        Address address;
        try {
            address = addrFactory.getAddress(addressStr);
        } catch (Exception e) {
            return result;
        }
        if (address == null) return result;

        Listing listing = program.getListing();
        Instruction instr = listing.getInstructionAt(address);

        while (instr != null) {
            Map<String, Object> instrInfo = new LinkedHashMap<>();
            instrInfo.put("address", instr.getAddress().toString());
            instrInfo.put("mnemonic", instr.getMnemonicString());

            // Get p-code for this instruction
            try {
                var pcode = instr.getPcode();
                List<Map<String, Object>> opsList = new ArrayList<>();
                if (pcode != null) {
                    for (var op : pcode) {
                        Map<String, Object> opInfo = new LinkedHashMap<>();
                        opInfo.put("opcode", op.getMnemonic());
                        opInfo.put("seqnum", op.getSeqnum() != null ? op.getSeqnum().toString() : "unknown");
                        opsList.add(opInfo);
                    }
                }
                instrInfo.put("pcode_ops", opsList);
            } catch (Exception e) {
                instrInfo.put("pcode_error", e.getMessage());
            }

            result.add(instrInfo);
            instr = listing.getInstructionAfter(instr.getAddress());
        }

        return result;
    }
}