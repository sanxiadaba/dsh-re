// re 的反编译脚本：定位函数，把反编译 C 写到文件（不往 stdout 混日志）。
// 用法：analyzeHeadless ... -postScript DumpFunction.java <0xADDR | sym:NAME> <outfile>
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import java.io.PrintWriter;

public class DumpFunction extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("RE_BAD_ARGS");
            return;
        }
        FunctionManager manager = currentProgram.getFunctionManager();
        Function target = null;
        Address address = null;
        if (args[0].startsWith("sym:")) {
            String wanted = args[0].substring(4);
            for (Function function : manager.getFunctions(true)) {
                if (function.getName().equals(wanted)) { target = function; break; }
            }
        } else {
            address = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(args[0]);
            if (address != null) {
                target = manager.getFunctionContaining(address);
            }
        }
        if (target == null && address != null) {
            disassemble(address);
            target = createFunction(address, null);
        }
        if (target == null) {
            println("RE_NO_FUNCTION");
            return;
        }
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        DecompileResults results = decompiler.decompileFunction(target, 120, monitor);
        if (results == null || !results.decompileCompleted()) {
            println("RE_FAILED " + (results == null ? "null" : results.getErrorMessage()));
            return;
        }
        try (PrintWriter out = new PrintWriter(args[1], "UTF-8")) {
            out.println("RE_FUNC " + target.getName() + " " + target.getEntryPoint());
            out.print(results.getDecompiledFunction().getC());
        }
        println("RE_OK " + args[1]);
    }
}
