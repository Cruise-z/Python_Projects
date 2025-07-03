from tree_sitter import Language, Parser
from utils import *
import sys
import os
import json
from tqdm import tqdm


if __name__ == '__main__':
    # struct_doc('java', 
    #            "4bit_gru_srcmarker_42_csn_java_tag1_2.jsonl", 
    #            ObfusType.tag1_2)
    
    # doc2embedData(ObfusType.tag1_2)
    
    # code = sys.stdin.read()
    # content = prompt_gen(code, 'java', ObfusType.tag1_2)
    # print(content)
    
    code1 = """
    public class example {
        public boolean blockingAwait(long timeout, TimeUnit unit) {
            int a = 1, b = 2, c;
            for (int i = 0; i < 10; i++) {}
            if (getCount() != 0) {
                try {
                    BlockingHelper.verifyNonBlocking();
                    if (!await(timeout, unit)) {
                        dispose();
                        return false;
                    }
                } catch (InterruptedException ex) {
                    dispose();
                    throw ExceptionHelper.wrapOrThrow(ex);
                }
            }
            Throwable ex = error;
            if (ex != null) {
                throw ExceptionHelper.wrapOrThrow(ex);
            }
            return true;
        }
    }
"""

    code2 = """public void testFunction(int input) {
        int a = 10;
        int b;
        b = input;
        int c = 1;
        c += 2;
        c = 3;
        int d;
        d += a;
        int e = 42;

        int f;
        System.out.println(f); 

        int g;
        g = 100;
        int h = g + 1;
    }"""
    
    code2 = "public PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails buildDetails(\n\t\t\tHttpServletRequest context) {\n\n\t\tCollection<String> j2eeUserRoles = getUserRoles(context);\n\t\tCollection<? extends GrantedAuthority> userGas = j2eeUserRoles2GrantedAuthoritiesMapper\n\t\t\t\t.getGrantedAuthorities(j2eeUserRoles);\n\n\t\tif (logger.isDebugEnabled()) {\n\t\t\tlogger.debug(\"J2EE roles [\" + j2eeUserRoles\n\t\t\t\t\t+ \"] mapped to Granted Authorities: [\" + userGas + \"]\");\n\t\t}\n\n\t\tPreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails result = new PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails(\n\t\t\t\tcontext, userGas);\n\n\t\treturn result;\n\t}"

    
    # format_code1 = format_func("example", code1, 'java')
    # format_code2 = format_func("example", code2, 'java')
    # print(format_code1)
    # # print(code1)
    # print(attach_lineNum_func(format_code1))
    # print(attach_lineNum_func(format_code2))

    # insert_pos = varScopeGaps(format_code2, "true", 20, 24)
    # formatted_str = json.dumps(insert_pos, indent=2, ensure_ascii=False)
    # print(formatted_str)
    
    
    # printAST(code1, 'java')
    # printAST(code1, 'java', text=True)
    
    code1 = """
    public class example {
        public boolean blockingAwait(long timeout, TimeUnit unit) {
            int m;
            m = 0;
            LinkedList < Cookie > x, y ,z = new LinkedList < Cookie > ( );
            x = 6;
            Throwable ex;
            y = 3;
            if (getCount() != 0) {
                try {
                    BlockingHelper.verifyNonBlocking();
                    if (!await(timeout, unit)) {
                        dispose();
                        return false;
                    }
                } catch (InterruptedException ex) {
                    dispose();
                    throw ExceptionHelper.wrapOrThrow(ex);
                }
            }
            if (z == 5){
                if (z == 5) {
                    
                }
                for (int i = 0; i < 10; i++) {
                    try{
                        // some code
                    } catch (Exception e) {
                        // handle exception
                        ex = error;
                    }
                }
            }
            if (ex != null) {
                throw ExceptionHelper.wrapOrThrow(ex);
            }
            return true;
        }
    }
"""
    
    lang = 'java'
    zroot = build_zast(code1, lang)
    print_zast(zroot)
    decls = find_local_varDecls(zroot)
    print(decls)
    var = decls[1]
    print(f"variable declaration is: {var[0]}")
    Fblock = find_scopeNode(var[1], lang)
    print(Fblock.type)
    print(Fblock.children)
    
    initFNode, isInit = find_initFNode(var[0], Fblock)
    print(initFNode)
    print(initFNode.type)
    print(initFNode.children)
    print(initFNode.parent == Fblock)
    
    index = find_insertion_points(var[0], Fblock, var[1])
    print(f"index of insertion points: {index}")
    
    print_ZASTNode(var[1])
    declNode, initNode, isempty = extractVarDecl(var[0], var[1])
    if declNode:
        print_ZASTNode(declNode)
    if initNode:
        print_ZASTNode(initNode)
    print_ZASTNode(var[1])
    print(isempty)
    
    # 假设你的输出结果是 ret
    # funcs, params, locals_, catches, foreach_vars, lambda_params = extract_renameable_entities(format_code2, wparser)

    # print_renameable_entities([funcs, params, locals_, catches, foreach_vars, lambda_params])

    
    
    # diff = tagDiff("tag1_2", wparser, format_code1, format_code2)
    
    # print(diff)
    
    
    
