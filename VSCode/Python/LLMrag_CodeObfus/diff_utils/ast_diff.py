from tree_sitter import Language, Parser
from utils import *
import os
import json
from tqdm import tqdm


if __name__ == '__main__':
    struct_doc('java', 
               "4bit_gru_srcmarker_42_csn_java_tag1_2.jsonl", 
               ObfusType.tag1_2)
    
    doc2embedData(ObfusType.tag1_2)
    
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
    
    # code2 = "public boolean blockingAwait ( long timeout , TimeUnit unit ) { if ( getCount ( ) != 0 ) { try { BlockingHelper.verifyNonBlocking ( ) ; if ( ! await ( timeout , unit ) ) { dispose ( ) ; return false ; } } catch ( InterruptedException ex ) { dispose ( ) ; throw ExceptionHelper.wrapOrThrow ( ex ) ; } } Throwable ex ; ex = error ; if ( ex != null ) { throw ExceptionHelper.wrapOrThrow ( ex ) ; } return true ; }"
    
    # LANGUAGE = 'java'
    # wparser = WParser(LANGUAGE)

    
    # format_code1 = format_func("example", code1, 'java')
    # format_code2 = format_func("example", code2, 'java')
    # # # print(code1)
    # # print(attach_lineNum_func(format_code1))
    # # print(attach_lineNum_func(format_code2))
    
    # printAST(code1, 'java')
    
    # # 假设你的输出结果是 ret
    # # funcs, params, locals_, catches, foreach_vars, lambda_params = extract_renameable_entities(format_code2, wparser)

    # # print_renameable_entities([funcs, params, locals_, catches, foreach_vars, lambda_params])

    
    
    # # diff = tagDiff("tag1_2", wparser, format_code1, format_code2)
    
    # # print(diff)
    
    
    
