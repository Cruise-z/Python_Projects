from tree_sitter import Language, Parser
import sys
import os
import json
from tqdm import tqdm

sys.path.append(os.path.abspath('./diff_utils'))
from utils import *


if __name__ == '__main__':
    code1 = """
// test 1: var[0]: m
// test 2: var[1]: n
// test 3: var[2,3,4]: x,y,z
// test 4: var[5]: ex
// test 5: var[6]: j
// test 6: var[7]: i
public class example {
    public bool blockingAwait(long timeout, TimeUnit unit) {
        LinkedList < Cookie > m;
        m = 0;
        LinkedList < Cookie > n = 666;
        LinkedList < Cookie > x, y ,z = new LinkedList < Cookie > ( );
        x = 6;
        Throwable ex;
        y = 3;
        int j;
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
                z+=1;
            }
            for (i = 0; i < 10; i++) {
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
        while(1){
            while(true){
                if (z == 5){
                    break;
                }
            }
        }
        do {
            z = z++;
        }while(z != 5);
        return true;
    }
}
"""
    # code1 = """void testFunction(int input) {
    #     int a = 10;
    #     int b;
    #     b = input;
    #     int h = 0;
    #     h = h + 1;
    # }"""
    
    code1 = """
void loop_example() {
    // 1. for loop
    int i = 3;
    int j;
    j = 3;
    for (i = 0; i < 5; i++) {
        std::cout << "For loop: " << i << std::endl;
    }

    // 2. range-based for loop (C++11+)
    std::vector<int> nums = {1, 2, 3};
    for (int n : nums) {
        std::cout << "Range-for: " << n << std::endl;
    }

    // 3. while loop
    int count = 0;
    while (count < 3) {
        std::cout << "While loop: " << count << std::endl;
        count++;
    }

    // 4. do-while loop
    int k = 0;
    do {
        std::cout << "Do-while: " << k << std::endl;
        k++;
    } while (k < 2);
}
"""
    
    code1 = """
void loop_example() {
    // int k = 0;
    int count = 0;
    while (count < 3) {
        std::cout << "While loop: " << count << std::endl;
        count++;
    }
}
"""
    
    lang = 'cpp'
    zroot = build_zast(code1, lang)
    print_zast(zroot)
    
    # decls = find_local_varDecls(zroot)
    # print(decls)
    # var = decls[5]
    # print(f"variable declaration is: {var[0]}")
    # Fblock = find_scopeNode(var[1], lang)
    # print(Fblock.type)
    # print(Fblock.children)
    
    # initFNode, isDirect = find_initFNode(var[0], Fblock)
    # if initFNode:
    #     print_ZASTNode(initFNode)
    #     print(initFNode.type)
    #     print(initFNode.children)
    #     print(initFNode.parent == Fblock)
    # highlight_print(f"isDirect?:{isDirect}")
    
    # highlight_print(f"Original decNode:")
    # print_ZASTNode(var[1])
    # declNode, initNode, oriInitIdx, index, isempty = reorg_varDecl(var[0], Fblock, var[1])
    # highlight_print(f"After process:")
    # highlight_print(f"Original_processed")
    # print_ZASTNode(var[1])
    # highlight_print(f"Declaration")
    # print_ZASTNode(declNode)
    # if initNode:
    #     highlight_print(f"Initialization")
    #     print_ZASTNode(initNode)
    # highlight_print(f"ori_decnode is empty: {isempty}")
    # print(f"index of insertion points: {index}")
    
    # reposVarDecl(var[0], var[1], lang)
    # reposVarsDecl(zroot, lang)
    
    # whileCondTrans(zroot)
    # updateIncDec(zroot)
    random_loop_conversion(zroot, lang)
    print_ZASTNode(zroot)
    # zjson = zroot.json()
    # print(json.dumps(zjson, indent=2))

    