# regWM.py
from server import register_internal, register_external_builder, vocab_ids

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

# ===== 纯 builder 化：仅注册可参数化 builder =====
def build_wllm(**cfg):
    gamma = cfg.get("gamma", 0.5)
    delta = cfg.get("delta", 1)
    # vocab 由服务端注入 vocab_ids，这里不从 cfg 读取
    return WLLM(vocab=vocab_ids, gamma=gamma, delta=delta)

def build_sweet(**cfg):
    gamma = cfg.get("gamma", 0.5)
    delta = cfg.get("delta", 1)
    entropy_threshold = cfg.get("entropy_threshold", 0.9)
    return Sweet(vocab=vocab_ids, gamma=gamma, delta=delta, entropy_threshold=entropy_threshold)

register_external_builder("wllm", build_wllm)
register_external_builder("sweet", build_sweet)