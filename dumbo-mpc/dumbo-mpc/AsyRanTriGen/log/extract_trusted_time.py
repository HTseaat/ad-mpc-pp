import os
import re
import csv
from collections import defaultdict

LOG_ROOT = "."         # 当前目录
COMMITTEE_SIZE = 4     # 每层节点数

# 匹配文件名 logs-<idx>.log
fn_pattern = re.compile(r'^logs-(\d+)\.log$')

# 匹配日志中的时间字段
trans_foll_pattern  = re.compile(r'layer ID:\s*(\d+)\s+trans_foll_time:\s*([\d\.eE+-]+)')
mul_foll_pattern    = re.compile(r'layer ID:\s*(\d+)\s+mul_foll_time:\s*([\d\.eE+-]+)')
layer_time_pattern  = re.compile(r'layer ID:\s*(\d+)\s+layer_time:\s*([\d\.eE+-]+)')

# data[key=(node, layer)] = { 'trans_foll_time': ..., 'mul_foll_time': ..., 'layer_time': ... }
data = {}

for root, dirs, files in os.walk(LOG_ROOT):
    for fn in files:
        m = fn_pattern.match(fn)
        if not m:
            continue
        file_idx = int(m.group(1))
        node_id = file_idx % COMMITTEE_SIZE
        layer_id_from_file = file_idx // COMMITTEE_SIZE  # 如果需要，也可以用这个

        path = os.path.join(root, fn)
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                for pattern, key in (
                    (trans_foll_pattern, 'trans_foll_time'),
                    (mul_foll_pattern,   'mul_foll_time'),
                    (layer_time_pattern, 'layer_time'),
                ):
                    lm = pattern.search(line)
                    if lm:
                        layer_from_log = int(lm.group(1))
                        # 这里你可以选择使用日志里的 layer ID，或者用文件推出来的 layer_id_from_file
                        layer = layer_from_log
                        value = float(lm.group(2))
                        data.setdefault((node_id, layer), {})[key] = value

# 先按节点分组
grouped = defaultdict(list)
for (node, layer), vals in data.items():
    grouped[node].append({'node': node, 'layer': layer, **vals})

rows = []
for node, recs in grouped.items():
    # 按层排序
    recs_sorted = sorted(recs, key=lambda r: r['layer'])
    prev_layer_time = None
    for rec in recs_sorted:
        tf = rec.get('trans_foll_time', None)
        mf = rec.get('mul_foll_time', None)
        lt = rec.get('layer_time', None)

        # 计算 real_trans_time = trans_foll_time - 上一层 layer_time
        if tf is not None and prev_layer_time is not None:
            real_trans_time = tf - prev_layer_time
        else:
            # 第一层或者缺少上一层 layer_time 的情况，就用原始 tf 或 0
            real_trans_time = tf if tf is not None else 0.0

        # 计算 trusted_verification_time = real_trans_time + mul_foll_time
        mul_foll = mf if mf is not None else 0.0
        trusted_verification_time = real_trans_time + mul_foll

        rec['real_trans_time'] = real_trans_time
        rec['trusted_verification_time'] = trusted_verification_time

        # 更新 prev_layer_time 为当前层的 layer_time（如果有）
        if lt is not None:
            prev_layer_time = lt

        rows.append(rec)

# 写出逐节点逐层的 CSV
out_csv = "trusted_times.csv"
fieldnames = [
    'node', 'layer',
    'trans_foll_time', 'mul_foll_time', 'layer_time',
    'real_trans_time', 'trusted_verification_time',
]

with open(out_csv, 'w', newline='', encoding='utf-8') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for row in sorted(rows, key=lambda r: (r['node'], r['layer'])):
        out_row = {}
        for k in fieldnames:
            v = row.get(k, '')
            out_row[k] = v
        writer.writerow(out_row)

print(f"trusted_verification_time written to {out_csv}")

# 计算每层平均的 trusted_verification_time
layer_group = defaultdict(list)
for rec in rows:
    layer = rec['layer']
    tvt = rec.get('trusted_verification_time', None)
    if tvt is not None:
        layer_group[layer].append(tvt)

layer_avg_rows = []
for layer, vals in layer_group.items():
    if not vals:
        continue
    avg_tvt = sum(vals) / len(vals)
    layer_avg_rows.append({
        'layer': layer,
        'avg_trusted_verification_time': avg_tvt,
        'num_nodes': len(vals),
    })

# 写出每层平均 trusted_verification_time 的 CSV
avg_out_csv = "trusted_times_layer_avg.csv"
with open(avg_out_csv, 'w', newline='', encoding='utf-8') as csvfile:
    fieldnames_avg = ['layer', 'avg_trusted_verification_time', 'num_nodes']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames_avg)
    writer.writeheader()
    for row in sorted(layer_avg_rows, key=lambda r: r['layer']):
        writer.writerow(row)

print(f"Per-layer average trusted_verification_time written to {avg_out_csv}")

# ------------------------------------------------------------
# 按你的规则计算整体平均 trusted_verification_time
# 例：总层数 L=8，层号 0~7
#     分母 = L - 3 = 5
#     分子 = layer 6,5,4,3,2 这几层的 avg_trusted_verification_time 之和
# 通用规则（层号从 0 开始）：
#   - 排除最后 1 层 (layer = L-1)
#   - 排除最前 2 层 (layer = 0,1)
#   - 用中间的 layer 2 ~ layer (L-2) 这些层，一共 L-3 层
# ------------------------------------------------------------
layer_avg_rows_sorted = sorted(layer_avg_rows, key=lambda r: r['layer'])
total_layers = len(layer_avg_rows_sorted)

trimmed_avg_tvt = None
used_layers = 0

if total_layers > 3:
    # 下标 0,1 是 layer 0,1；下标 total_layers-1 是最后一层
    start_idx = 2                   # 对应 layer 2
    end_idx = total_layers - 1      # 不包含最后一层 layer (L-1)
    effective_rows = layer_avg_rows_sorted[start_idx:end_idx]

    used_layers = len(effective_rows)   # 应该等于 total_layers - 3
    if used_layers > 0:
        sum_tvt = sum(r['avg_trusted_verification_time'] for r in effective_rows)
        trimmed_avg_tvt = sum_tvt / used_layers
else:
    trimmed_avg_tvt = None
    used_layers = 0

# 输出到单独的 CSV，方便后续脚本或画图使用
summary_avg_out_csv = "trusted_times_overall_avg_trimmed.csv"
with open(summary_avg_out_csv, 'w', newline='', encoding='utf-8') as csvfile:
    fieldnames_summary = [
        'total_layers',
        'used_layers',  # 实际参与计算平均的层数（应为 total_layers - 3）
        'trimmed_avg_trusted_verification_time',
    ]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames_summary)
    writer.writeheader()
    if trimmed_avg_tvt is not None:
        writer.writerow({
            'total_layers': total_layers,
            'used_layers': used_layers,
            'trimmed_avg_trusted_verification_time': trimmed_avg_tvt,
        })
    else:
        writer.writerow({
            'total_layers': total_layers,
            'used_layers': 0,
            'trimmed_avg_trusted_verification_time': '',
        })

if trimmed_avg_tvt is not None:
    print(
        "Trimmed overall avg_trusted_verification_time "
        f"(use layers 2..{total_layers-2}, exclude first 2 and last 1): {trimmed_avg_tvt}"
    )
else:
    print("Not enough layers to compute trimmed overall average (need > 3 layers).")