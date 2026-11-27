// re 的批量反编译脚本：把目标里所有函数反编译到一个文件。
// 用法：analyzeHeadless ... -postScript DumpAll.java <outfile> [seeds.txt]
//   seeds.txt 每行一个 0x 地址：反编译前先在这些地址建函数。
//   固件必需——Ghidra 的 BinaryLoader 不知道向量表，Reset/NMI/ISR 根本不会成为函数。
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

public class DumpAll extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("RE_BAD_ARGS");
            return;
        }
        int created = seedFunctions(args.length > 1 ? args[1] : null);
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        FunctionManager manager = currentProgram.getFunctionManager();
        int total = 0, ok = 0;
        try (PrintWriter out = new PrintWriter(args[0], "UTF-8")) {
            out.println("// seeded functions before analysis: " + created);
            for (Function function : manager.getFunctions(true)) {
                total++;
                out.println("// === " + function.getName() + " @ " + function.getEntryPoint()
                        + " size=" + function.getBody().getNumAddresses());
                DecompileResults results = decompiler.decompileFunction(function, 90, monitor);
                if (results != null && results.decompileCompleted()
                        && results.getDecompiledFunction() != null) {
                    out.println(results.getDecompiledFunction().getC());
                    ok++;
                } else {
                    out.println("/* decompile failed */");
                }
                out.println();
            }
        }
        println("RE_DONE " + ok + "/" + total);
    }

    private int seedFunctions(String seedFile) {
        if (seedFile == null) {
            return 0;
        }
        int created = 0;
        try {
            List<String> lines = Files.readAllLines(Paths.get(seedFile));
            FunctionManager manager = currentProgram.getFunctionManager();
            for (String line : lines) {
                String text = line.trim();
                if (text.isEmpty() || text.startsWith("#")) {
                    continue;
                }
                Address addr = toAddr(text);
                if (addr == null || manager.getFunctionAt(addr) != null) {
                    continue;
                }
                try {
                    disassemble(addr);
                    createFunction(addr, null);
                    created++;
                } catch (Exception ignored) {
                    // 有些种子不是有效指令边界，跳过即可
                }
            }
        } catch (Exception ex) {
            println("RE_SEEDS_FAILED " + ex.getMessage());
        }
        return created;
    }
}
