import os
import re
import csv
import argparse
from collections import defaultdict

parser = argparse.ArgumentParser(description="Extract timing metrics from node logs")
parser.add_argument("--logdir", default="logs",
                    help="Directory where node_*.log files are located (default: ./logs)")
parser.add_argument("--out_csv", default="extracted_times.csv",
                    help="Output CSV for per-layer metrics")
parser.add_argument("--summary_csv", default="summary_times.csv",
                    help="Output CSV for per-node totals + averages")
args = parser.parse_args()

LOG_ROOT = args.logdir

# 匹配文件名中的节点号和层号
fn_pattern = re.compile(r'node(\d+)_cont(\d+)\.log$')

# 匹配需要的新字段
trans_pattern     = re.compile(r'layer ID:\s*(\d+)\s+trans_pre_time:\s*([\d\.eE+-]+)')
mul_pre_pattern   = re.compile(r'layer ID:\s*(\d+)\s+mul_pre_time:\s*([\d\.eE+-]+)')
trans_foll_pattern= re.compile(r'layer ID:\s*(\d+)\s+trans_foll_time:\s*([\d\.eE+-]+)')
mul_foll_pattern  = re.compile(r'layer ID:\s*(\d+)\s+mul_foll_time:\s*([\d\.eE+-]+)')
exec_pattern      = re.compile(r'layer ID:\s*(\d+)\s+exec_time:\s*([\d\.eE+-]+)')
layer_time_pattern= re.compile(r'layer ID:\s*(\d+)\s+layer_time:\s*([\d\.eE+-]+)')

# 存储节点和层对应的时间数据
data = {}  # key: (node, layer), value: dict

for root, dirs, files in os.walk(LOG_ROOT):
    for fn in files:
        m = fn_pattern.match(fn)
        if not m:
            continue
        node_id = int(m.group(1))
        path = os.path.join(root, fn)
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                for pattern, key in (
                    (trans_pattern,     'trans_pre_time'),
                    (mul_pre_pattern,   'mul_pre_time'),
                    (trans_foll_pattern,'trans_foll_time'),
                    (mul_foll_pattern,  'mul_foll_time'),
                    (exec_pattern,      'exec_time'),
                    (layer_time_pattern,'layer_time'),
                ):
                    lm = pattern.search(line)
                    if lm:
                        layer = int(lm.group(1))
                        value = float(lm.group(2))
                        data.setdefault((node_id, layer), {})[key] = value

# 汇总所有记录（可能缺失某些字段的层也会保留）
rows = []
for (node, layer), vals in data.items():
    rows.append({
        'node': node,
        'layer': layer,
        'trans_pre_time':  vals.get('trans_pre_time', ''),
        'mul_pre_time':    vals.get('mul_pre_time', ''),
        'trans_foll_time': vals.get('trans_foll_time', ''),
        'mul_foll_time':   vals.get('mul_foll_time', ''),
        'exec_time':       vals.get('exec_time', ''),
        'layer_time':      vals.get('layer_time', ''),
    })

# 调整每个节点的 trans_foll_time，减去上一层的 layer_time
grouped = defaultdict(list)
for rec in rows:
    grouped[rec['node']].append(rec)

adjusted = []
for node, recs in grouped.items():
    recs_sorted = sorted(recs, key=lambda x: x['layer'])
    prev_layer_time = 0.0
    for rec in recs_sorted:
        tf = rec.get('trans_foll_time', '')
        if tf != '':
            try:
                rec['trans_foll_time'] = float(tf) - prev_layer_time
            except:
                pass
        lt = rec.get('layer_time', '')
        if lt != '':
            try:
                prev_layer_time = float(lt)
            except:
                pass
        adjusted.append(rec)
rows = adjusted

# 将结果写入 per-layer CSV
with open(args.out_csv, 'w', newline='', encoding='utf-8') as csvfile:
    fieldnames = [
        'node', 'layer',
        'trans_pre_time', 'mul_pre_time',
        'trans_foll_time', 'mul_foll_time',
        'exec_time', 'layer_time'
    ]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for row in sorted(rows, key=lambda r: (r['node'], r['layer'])):
        writer.writerow(row)
print(f"✓ Per-layer metrics written to {args.out_csv}")

# 计算每个节点的总时间和全局平均（只统计 mul、trans、exec）
agg = defaultdict(lambda: {'mul': 0.0, 'trans': 0.0, 'exec': 0.0})
for rec in rows:
    node = rec['node']
    # mul 时间累加
    mp = rec.get('mul_pre_time', '')
    mf = rec.get('mul_foll_time', '')
    agg[node]['mul']   += (float(mp) if mp != '' else 0.0) + (float(mf) if mf != '' else 0.0)
    # trans 时间累加
    tp = rec.get('trans_pre_time', '')
    tf = rec.get('trans_foll_time', '')
    agg[node]['trans'] += (float(tp) if tp != '' else 0.0) + (float(tf) if tf != '' else 0.0)
    # exec 时间累加
    ex = rec.get('exec_time', '')
    agg[node]['exec']  += (float(ex) if ex != '' else 0.0)

# 全局平均
nodes = sorted(agg.keys())
n_nodes    = len(nodes)
total_mul   = sum(v['mul']   for v in agg.values())
total_trans= sum(v['trans'] for v in agg.values())
total_exec = sum(v['exec']  for v in agg.values())
avg_mul    = total_mul   / n_nodes if n_nodes else 0.0
avg_trans  = total_trans / n_nodes if n_nodes else 0.0
avg_exec   = total_exec  / n_nodes if n_nodes else 0.0

# 写入 per-node summary CSV
with open(args.summary_csv, 'w', newline='', encoding='utf-8') as fsum:
    writer_sum = csv.writer(fsum)
    writer_sum.writerow(['node', 'total_mul', 'total_trans', 'total_exec'])
    for node in nodes:
        v = agg[node]
        writer_sum.writerow([node, v['mul'], v['trans'], v['exec']])
    writer_sum.writerow(['average', avg_mul, avg_trans, avg_exec])
print(f"✓ Per-node totals & averages written to {args.summary_csv}")