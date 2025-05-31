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
    
    code1 = "public OAuth2ClientConfigurer<HttpSecurity> oauth2Client() throws Exception {\n\t\tOAuth2ClientConfigurer<HttpSecurity> configurer = getOrApply(new OAuth2ClientConfigurer<>());\n\t\tthis.postProcess(configurer);\n\t\treturn configurer;\n\t}"

    code2 = "public OAuth2ClientConfigurer<HttpSecurity> WhfqbiwFunc() throws Exception {\n    OAuth2ClientConfigurer<HttpSecurity> styleable = getOrApply(new OAuth2ClientConfigurer<>());\n    this.postProcess(styleable);\n    return styleable;\n}"
    
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

    
    
    diff = compare_all_entities(wparser, format_code1, format_code2)
    
    print(diff)
    
    
    
