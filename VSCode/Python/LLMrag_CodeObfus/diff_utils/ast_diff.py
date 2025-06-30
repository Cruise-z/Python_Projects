from tree_sitter import Language, Parser
from utils import *
import sys
import os
import json
from tqdm import tqdm


if __name__ == '__main__':
    struct_doc('java', 
               "4bit_gru_srcmarker_42_csn_java_tag1_2.jsonl", 
               ObfusType.tag1_2)
    
    doc2embedData(ObfusType.tag1_2)
    
    # code = sys.stdin.read()
    # content = prompt_gen(code, 'java', ObfusType.tag1_2)
    # print(content)
    
    # code1 = "public boolean blockingAwait(long timeout, TimeUnit unit) {\n        if (getCount() != 0) {\n            try {\n                BlockingHelper.verifyNonBlocking();\n                if (!await(timeout, unit)) {\n                    dispose();\n                    return false;\n                }\n            } catch (InterruptedException ex) {\n                dispose();\n                throw ExceptionHelper.wrapOrThrow(ex);\n            }\n        }\n        Throwable ex = error;\n        if (ex != null) {\n            throw ExceptionHelper.wrapOrThrow(ex);\n        }\n        return true;\n    }"

    # code2 = """public void testFunction(int input) {
    #     int a = 10;
    #     int b;
    #     b = input;
    #     int c = 1;
    #     c += 2;
    #     c = 3;
    #     int d;
    #     d += a;
    #     int e = 42;

    #     int f;
    #     System.out.println(f); 

    #     int g;
    #     g = 100;
    #     int h = g + 1;
    # }"""
    
    # code2 = "public PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails buildDetails(\n\t\t\tHttpServletRequest context) {\n\n\t\tCollection<String> j2eeUserRoles = getUserRoles(context);\n\t\tCollection<? extends GrantedAuthority> userGas = j2eeUserRoles2GrantedAuthoritiesMapper\n\t\t\t\t.getGrantedAuthorities(j2eeUserRoles);\n\n\t\tif (logger.isDebugEnabled()) {\n\t\t\tlogger.debug(\"J2EE roles [\" + j2eeUserRoles\n\t\t\t\t\t+ \"] mapped to Granted Authorities: [\" + userGas + \"]\");\n\t\t}\n\n\t\tPreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails result = new PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails(\n\t\t\t\tcontext, userGas);\n\n\t\treturn result;\n\t}"
    
    # LANGUAGE = 'java'
    # wparser = WParser(LANGUAGE)

    
    # # format_code1 = format_func("example", code1, 'java')
    # format_code2 = format_func("example", code2, 'java')
    # print(format_code2)
    # # # print(code1)
    # # print(attach_lineNum_func(format_code1))
    # # print(attach_lineNum_func(format_code2))

    # # insert_pos = varScopeGaps(format_code2, "true", 20, 24)
    # # formatted_str = json.dumps(insert_pos, indent=2, ensure_ascii=False)
    # # print(formatted_str)
    
    
    # # printAST(code1, 'java')
    
    # # 假设你的输出结果是 ret
    # # funcs, params, locals_, catches, foreach_vars, lambda_params = extract_renameable_entities(format_code2, wparser)

    # # print_renameable_entities([funcs, params, locals_, catches, foreach_vars, lambda_params])

    
    
    # # diff = tagDiff("tag1_2", wparser, format_code1, format_code2)
    
    # # print(diff)
    
    
    
