import math
from typing import List, Dict, Optional

import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
from transformers.generation.logits_process import PrefixConstrainedLogitsProcessor, LogitsProcessorList
from structDB import retrieve_reference
from utils import *
import os
# os.environ["CUDA_LAUNCH_BLOCKING"] = "1"

from watermark import WatermarkLogitsProcessor
from sweet import SweetLogitsProcessor

# 1) 初始化引擎（可换任意 HF CausalLM）
engine = HFModelEngine(
    model_name="bigcode/starcoder",   # 换 model 只改这里
    device_map=None,                  # 单卡最稳；需要分片用 "auto"
    fp16=True,
)

wllm_processor = WatermarkLogitsProcessor(vocab=list(engine.tokenizer.get_vocab().values()),
                                               gamma=0.5,
                                               delta=1)

sweet_processor = SweetLogitsProcessor(vocab=list(engine.tokenizer.get_vocab().values()),
                                       gamma=0.5,
                                       delta=1,
                                       entropy_threshold=0.9)

# 2) 适配你的 retriever
retriever = FunctionRetriever(retrieve_reference)

# 3) 编排器
rag_gen = RagConstrainedGenerator(engine, retriever)

prompt = "Task: use java Create a snake game ..."
prefix = "package correct;\nimport javax.swing.*; ..."

# A) 自适应软约束（推荐，等效硬夹紧但形式“软”）：
res = rag_gen.generate(
    prompt, prefix,
    top_k=1,
    constraint="adaptive",    # 'adaptive' | 'fixed' | 'hard'
    gamma = 2.5,
    alpha = 0.65,
    lambda_start = 1.0,
    lambda_end = 1.0,
    schedule = "constant",   # "constant" | "linear"
    max_bias = 50.0,
    eps = 1e-12,
    compute_in_fp32 = False,
    finish_with_eos = True,
    ensure_copy = False,
    gamma_safe = 1e-6,
    fixed_bias = 12.0,
    # watermark_processor = None,
    watermark_processor=sweet_processor  # 这里可换成你自己的水印 Processor
)
print(res["route"], res["exact_match"], len(res["text"]))
print(res["text"])

# B) 固定偏置软约束：
# res2 = rag_gen.generate(prompt, prefix, constraint="fixed", fixed_bias=16.0)
# print(res2["route"], res2["exact_match"], len(res2["text"]))

# C) 硬夹紧（100%一致，用于极端对照）：
# res3 = rag_gen.generate(prompt, prefix, constraint="hard")
# print(res3["route"], res3["exact_match"], len(res3["text"]))