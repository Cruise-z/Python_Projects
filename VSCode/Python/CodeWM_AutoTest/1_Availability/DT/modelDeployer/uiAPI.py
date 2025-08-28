# user_processors.py
from server import register_internal, register_external, vocab_ids

# 示例A：把 HF 的 WatermarkLogitsProcessor 当作“内置”
# from transformers import WatermarkLogitsProcessor
# greenlist = WatermarkLogitsProcessor(
#     vocab_size=max(vocab_ids)+1,  # 或直接 tokenizer.vocab_size
#     device="cuda",                # 按需
#     greenlist_ratio=0.25,
#     bias=2.0,
#     hashing_key=123456789,
#     seeding_scheme="lefthash",
#     context_width=2,
# )
# register_internal("greenlist_default", greenlist)

# 示例B：你的自定义处理器，当作“外置”
from libWM.watermark import WatermarkLogitsProcessor as WLLM
from libWM.sweet import SweetLogitsProcessor as Sweet

wllm_processor = WLLM(
    vocab=vocab_ids,  # 你要求的传参方式
    gamma=0.5,
    delta=1
)
sweet_processor = Sweet(
    vocab=vocab_ids,
    gamma=0.5,
    delta=1,
    entropy_threshold=0.9
)

# 你可以把它们分别注册，也可以先组装成一个列表再注册成一个名字
register_external("wllm", wllm_processor)
register_external("sweet", sweet_processor)

# 也支持链式组合（示例：外置链 = wllm + sweet）
# from transformers import LogitsProcessorList
# register_external("wllm_plus_sweet", LogitsProcessorList([wllm_processor, sweet_processor]))
