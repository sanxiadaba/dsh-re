// re 的反编译脚本：定位函数并打印反编译 C。
// 用法：analyzeHeadless ... -postScript DumpFunction.java <0xADDR | sym:NAME>
// 地址没被识别成函数时，先反汇编再建函数，避免"入口没函数"就放弃。
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class DumpFunction extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        FunctionManager manager = currentProgram.getFunctionManager();
        Function target = null;
        Address address = null;
        if (args.length > 0 && args[0].startsWith("sym:")) {
            String wanted = args[0].substring(4);
            for (Function function : manager.getFunctions(true)) {
                if (function.getName().equals(wanted)) { target = function; break; }
            }
        } else if (args.length > 0) {
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
        println("RE_FUNC " + target.getName() + " " + target.getEntryPoint());
        println(results.getDecompiledFunction().getC());
    }
}
