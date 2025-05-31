from tree_sitter import Language, Parser
from utils import *
import os
import json
from tqdm import tqdm


if __name__ == '__main__':
    # struct_doc('java', 
    #            "4bit_gru_srcmarker_42_csn_java_tag1_1.jsonl", 
    #            "tag1_1.pkl",
    #            ObfusType.tag1_1)
    
    # doc2embedData("tag1_1.pkl")
    
    code1 = "@Subscribe(sticky = true, threadMode = ThreadMode.MAIN)\n    public void onEventMainThread(MediaEvent event) {\n        RTEditText editor = mEditors.get(mActiveEditor);\n        RTMedia media = event.getMedia();\n        if (editor != null && media instanceof RTImage) {\n            insertImage(editor, (RTImage) media);\n            EventBus.getDefault().removeStickyEvent(event);\n            mActiveEditor = Integer.MAX_VALUE;\n        }\n    }"

    code2 = "@Subscribe(sticky = true, threadMode = ThreadMode.MAIN)\npublic void A_aFzyiKNg_Zas_FDEZgL(MediaEvent Triangulations) {\n    RTEditText Editor = mEditors.get(mActiveEditor);\n    RTMedia Media = Triangulations.getMedia();\n    if (Editor != null && Media instanceof RTImage) {\n        insertImage(Editor, (RTImage) Media);\n        EventBus.getDefault().removeStickyEvent(Triangulations);\n        mActiveEditor = Integer.MAX_VALUE;\n    }\n}"
    
    LANGUAGE = 'java'
    wparser = WParser(LANGUAGE)

    
    format_code1 = format_func(code1, 'java')
    format_code2 = format_func(code2, 'java')
    # print(code1)
    print(attach_lineNum_func(format_code1))
    print(attach_lineNum_func(format_code2))
    
    # printAST(code1, 'java')
    
    # 假设你的输出结果是 ret
    # funcs, params, locals_, catches, foreach_vars, lambda_params = extract_renameable_entities(format_code2, parser)

    # print_renameable_entities([funcs, params, locals_, catches, foreach_vars, lambda_params])

    
    
    diff = tagDiff("tag1_2", wparser, format_code1, format_code2)
    
    print(diff)
    
    
    
