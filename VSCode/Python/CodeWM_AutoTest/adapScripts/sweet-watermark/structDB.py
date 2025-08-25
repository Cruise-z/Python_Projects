# pip install faiss-cpu torch transformers numpy rapidfuzz
import json
from pathlib import Path
import numpy as np
import torch
import faiss
from transformers import AutoTokenizer, AutoModel
from rapidfuzz import fuzz, process
import os
work_space = Path(__file__).resolve().parent
os.chdir(work_space)

# ========= 可替换：嵌入模型 =========
# 通用检索强：intfloat/e5-base-v2  （推荐）
# 代码检索可用：microsoft/codebert-base  或 jinaai/jina-embeddings-v2-base-code
EMBED_MODEL_NAME = "intfloat/e5-base-v2"

tokenizer = AutoTokenizer.from_pretrained(EMBED_MODEL_NAME)
encoder = AutoModel.from_pretrained(EMBED_MODEL_NAME)

def _prefix_for_e5(text, is_query: bool):
    # E5 家族建议加前缀
    if "intfloat/e5" in EMBED_MODEL_NAME:
        return f"{'query' if is_query else 'passage'}: {text}"
    return text

@torch.no_grad()
def encode_batch(texts, is_query=False, batch_size=16, max_length=512):
    """均值池化 + L2 归一化（用于余弦相似度/内积检索）"""
    out_list = []
    for i in range(0, len(texts), batch_size):
        batch = [_prefix_for_e5(t, is_query) for t in texts[i:i+batch_size]]
        inputs = tokenizer(batch, return_tensors="pt", truncation=True, padding=True, max_length=max_length)
        outputs = encoder(**inputs).last_hidden_state  # [B, L, H]
        mask = inputs["attention_mask"].unsqueeze(-1) # [B, L, 1]
        masked = outputs * mask
        mean_emb = masked.sum(dim=1) / mask.sum(dim=1).clamp(min=1)  # [B, H]
        vecs = mean_emb.cpu().numpy().astype("float32")
        # 归一化，配合内积=余弦相似度
        faiss.normalize_L2(vecs)
        out_list.append(vecs)
    return np.vstack(out_list)

def load_jsonl(jsonl_path):
    rows = []
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            if not line.strip():
                continue
            obj = json.loads(line)
            ref = obj.get("reference") or ""
            if not ref:
                continue
            rows.append({
                "task_id": obj.get("task_id", i),
                "task_name": obj.get("task_name", ""),
                "prompt": obj.get("prompt", ""),
                "prefix": obj.get("prefix", ""),
                "reference": ref
            })
    return rows

def make_passage_text(r):
    """构造入库文本：包含 task_name/prompt/prefix/reference 片段，提升可检索性"""
    ref_head = r["reference"][:2000]   # 视长度酌情截断
    pre_head = r["prefix"][:1000]
    prm_head = r["prompt"][:1000]
    parts = [
        f"[task_name] {r['task_name']}",
        f"[prompt] {prm_head}",
        f"[prefix] {pre_head}",
        f"[reference_head] {ref_head}"
    ]
    return "\n".join(parts)

def build_knowledge_base(
    jsonl_path,
    index_path="./knowledge_base.index",
    meta_path="./knowledge_meta.json"
):
    data = load_jsonl(jsonl_path)
    if not data:
        raise ValueError("JSONL 中没有可用记录（缺少 reference 字段）。")

    passages = [make_passage_text(r) for r in data]
    vecs = encode_batch(passages, is_query=False)  # passage 向量

    dim = vecs.shape[1]
    index = faiss.IndexFlatIP(dim)      # 余弦相似度（向量已 L2 归一化）
    index.add(vecs)
    faiss.write_index(index, index_path)

    meta = {
        "embed_model": EMBED_MODEL_NAME,
        "count": len(data),
        "rows": data
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    print(f"*索引: {Path(index_path).resolve()}")
    print(f"*元数据: {Path(meta_path).resolve()}")
    print(f"*文档数: {len(data)}")

def _load_kb(index_path, meta_path):
    index = faiss.read_index(index_path)
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    return index, meta

def _combine_text(prompt: str, prefix: str, max_len_prompt=2000, max_len_prefix=2000):
    p = (prompt or "")[:max_len_prompt]
    pre = (prefix or "")[:max_len_prefix]
    return (p + "\n" + pre).strip()

def retrieve_reference(
    query_text: str,
    top_k: int = 1,
    index_path: str = "./knowledge_base.index",
    meta_path: str = "./knowledge_meta.json",
    prefer_exact: bool = True,
    fuzzy_task_threshold: int = 85,
    fuzzy_pp_threshold: int = 80,
    vector_fallback: bool = True
):
    """
    多路检索合并：
      1) task_name 精确包含命中（优先）
      2) task_name 模糊匹配（WRatio）
      3) (prompt + prefix) 模糊匹配（WRatio）
      4) 以上不足 top_k 时，回退向量检索（余弦）
    返回：[{rank, score, task_id, task_name, prompt, prefix, reference, route}, ...]
    """
    index, meta = _load_kb(index_path, meta_path)
    rows = meta["rows"]

    # ---------- 1) task_name 精确包含 ----------
    ql = (query_text or "").lower().strip()
    if prefer_exact and ql:
        exact_hits = [i for i, r in enumerate(rows) if ql in (r.get("task_name") or "").lower()]
        if exact_hits:
            i = exact_hits[0]
            r = rows[i]
            return [{
                "rank": 1,
                "score": 1.0,
                "task_id": r["task_id"],
                "task_name": r.get("task_name", ""),
                "prompt": r.get("prompt", ""),
                "prefix": r.get("prefix", ""),
                "reference": r.get("reference", ""),
                "route": "task_name_exact"
            }]

    # 先收集多路候选（去重时保留最高分）
    cand = {}  # fid -> (score, route)

    # ---------- 2) task_name 模糊 ----------
    task_choices = [((r.get("task_name") or ""), i) for i, r in enumerate(rows)]
    if task_choices:
        # 取前若干名候选，提高召回；你也可把 limit 改成 len(rows) 全量打分
        task_top = process.extract(
            query_text, task_choices, scorer=fuzz.WRatio, limit=min(20, len(task_choices))
        )
        for (matched_text, i, score) in task_top:
            if score >= fuzzy_task_threshold:
                prev = cand.get(i)
                if (prev is None) or (score/100.0 > prev[0]):
                    cand[i] = (score/100.0, "task_name_fuzzy")

    # ---------- 3) (prompt + prefix) 模糊 ----------
    pp_choices = []
    for i, r in enumerate(rows):
        pp = _combine_text(r.get("prompt", ""), r.get("prefix", ""))
        pp_choices.append((pp, i))
    if pp_choices:
        pp_top = process.extract(
            query_text, pp_choices, scorer=fuzz.WRatio, limit=min(50, len(pp_choices))
        )
        for (matched_text, i, score) in pp_top:
            if score >= fuzzy_pp_threshold:
                prev = cand.get(i)
                if (prev is None) or (score/100.0 > prev[0]):
                    cand[i] = (score/100.0, "pp_fuzzy")

    # 将模糊候选按分数排序，截取 top_k
    fuzzy_results = sorted(cand.items(), key=lambda kv: kv[1][0], reverse=True)
    results = []
    for rank, (fid, (sc, route)) in enumerate(fuzzy_results[:top_k], 1):
        r = rows[fid]
        results.append({
            "rank": rank,
            "score": float(sc),
            "task_id": r["task_id"],
            "task_name": r.get("task_name", ""),
            "prompt": r.get("prompt", ""),
            "prefix": r.get("prefix", ""),
            "reference": r.get("reference", ""),
            "route": route
        })

    # ---------- 4) 向量回退 ----------
    if vector_fallback and len(results) < top_k:
        need = top_k - len(results)
        # 直接用 query_text 做向量检索（也可以改为 prompt+prefix 的拼接）
        from numpy import unique
        q_vec = encode_batch([query_text], is_query=True)  # 复用你前面定义的 encode_batch
        scores, idx = index.search(q_vec, need * 2)        # 多取一些，避免与 fuzzy 候选重复
        used_fids = set([rows.index(res) if isinstance(res, dict) else res for res in []])  # 兼容提醒

        used = set([int(rows.index(r)) for r in []])  # 无用行，仅防报错说明；可忽略
        picked = 0
        for sc, fid in zip(scores[0], idx[0]):
            if fid < 0:  # FAISS 可能返回 -1
                continue
            if int(fid) in cand:  # 避免与模糊候选重复
                continue
            r = rows[int(fid)]
            results.append({
                "rank": len(results) + 1,
                "score": float(sc),
                "task_id": r["task_id"],
                "task_name": r.get("task_name", ""),
                "prompt": r.get("prompt", ""),
                "prefix": r.get("prefix", ""),
                "reference": r.get("reference", ""),
                "route": "vector"
            })
            picked += 1
            if picked >= need:
                break

    # 最终仅保留 top_k
    return results[:top_k]

# ===== 使用示例 =====
# 先构建/重建索引（只需一次）
build_knowledge_base("./projectDev_java.jsonl")

# 查询
query = "snake game"
hits = retrieve_reference(query, top_k=1)
for h in hits:
    print(h["rank"], h["route"], h["task_name"], h["score"])
    print(h["reference"])