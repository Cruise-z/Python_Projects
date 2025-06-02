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
    
    # code1 = "protected final void fastPathOrderedEmit(U value, boolean delayError, Disposable disposable) {\n        final Observer<? super V> observer = downstream;\n        final SimplePlainQueue<U> q = queue;\n\n        if (wip.get() == 0 && wip.compareAndSet(0, 1)) {\n            if (q.isEmpty()) {\n                accept(observer, value);\n                if (leave(-1) == 0) {\n                    return;\n                }\n            } else {\n                q.offer(value);\n            }\n        } else {\n            q.offer(value);\n            if (!enter()) {\n                return;\n            }\n        }\n        QueueDrainHelper.drainLoop(q, observer, delayError, disposable, this);\n    }"

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
    
    # code2 = "protected final void fastPathOrderedEmit ( U value , boolean delayError , Disposable disposable ) { value = 1; final Observer < ? super V > observer ; observer = downstream ; final SimplePlainQueue < U > q ; q = queue ; if ( wip.get ( ) == 0 && wip.compareAndSet ( 0 , 1 ) ) { if ( q.isEmpty ( ) ) { accept ( observer , value ) ; if ( leave ( - 1 ) == 0 ) { return ; } } else { q.offer ( value ) ; } } else { q.offer ( value ) ; if ( ! enter ( ) ) { return ; } } QueueDrainHelper.drainLoop ( q , observer , delayError , disposable , this ) ; }"
    
    # LANGUAGE = 'java'
    # wparser = WParser(LANGUAGE)

    
    # format_code1 = format_func(code1, 'java')
    # format_code2 = format_func(code2, 'java')
    # # print(code1)
    # print(attach_lineNum_func(format_code1))
    # print(attach_lineNum_func(format_code2))
    
    # # printAST(code1, 'java')
    
    # # 假设你的输出结果是 ret
    # funcs, params, locals_, catches, foreach_vars, lambda_params = extract_renameable_entities(format_code2, wparser)

    # print_renameable_entities([funcs, params, locals_, catches, foreach_vars, lambda_params])

    
    
    # # diff = tagDiff("tag1_2", wparser, format_code1, format_code2)
    
    # # print(diff)
    
    
    
