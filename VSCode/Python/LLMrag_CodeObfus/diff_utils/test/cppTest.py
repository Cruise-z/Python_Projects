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
            for (int i = 0; i < 10; i=i+1) {
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
                
            }
        }
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
    # print_ZASTNode(zroot)
    # zjson = zroot.json()
    # print(json.dumps(zjson, indent=2))

    