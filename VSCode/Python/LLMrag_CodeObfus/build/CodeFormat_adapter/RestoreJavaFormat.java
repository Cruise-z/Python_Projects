import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.printer.PrettyPrinter;
import com.github.javaparser.printer.configuration.PrettyPrinterConfiguration;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Optional;

public class RestoreJavaFormat {
    public static void main(String[] args) throws Exception {
        // ✅ 从标准输入读取 Java 源码
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        StringBuilder codeBuilder = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            codeBuilder.append(line).append("\n");
        }
        String code = codeBuilder.toString();

        // ✅ 使用 JavaParser 解析源码
        JavaParser parser = new JavaParser(new ParserConfiguration());
        ParseResult<CompilationUnit> result = parser.parse(code);

        Optional<CompilationUnit> optionalCU = result.getResult();
        if (!optionalCU.isPresent()) {
            System.out.println("无法解析 Java 代码。");
            return;
        }

        CompilationUnit cu = optionalCU.get();

        // ✅ 配置格式化规则
        PrettyPrinterConfiguration config = new PrettyPrinterConfiguration();
        config.setIndentSize(4);
        config.setPrintComments(true);
        config.setColumnAlignFirstMethodChain(false);

        PrettyPrinter printer = new PrettyPrinter(config);
        String formatted = printer.print(cu);

        // ✅ 输出格式化结果
        System.out.println(formatted);
    }
}

