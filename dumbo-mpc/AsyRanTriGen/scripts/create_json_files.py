#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
create_conf.py

根据 run_key_gen_dyn.py 的逻辑，为每个节点生成配置 JSON 文件。
用法：
    python3 create_conf.py <protocol> <N> <t> <layers> <total_cm> [--run-id RUN_ID]

示例：
    python3 create_conf.py admpc 16 5 8 300
"""
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
import argparse
import os
import json
import base64
import uuid
from ctypes import *

# 导入 run_key_gen_dyn.py 中的函数和全局 lib
import run_key_gen_dyn as keygen
from run_key_gen_dyn import lib, generate_serialized_keys, acss_key_gen_with_srs

lib = CDLL("./kzg_ped_out.so")
lib.pyNewSRS.argtypes = [c_int]
lib.pyNewSRS.restype = c_char_p

lib.pyKeyGeneration.argtypes = [c_char_p, c_int]
lib.pyKeyGeneration.restype = c_char_p

# group = PairingGroup('SS512')
# group = PairingGroup('MNT159')
group = PairingGroup("MNT224")


def main():
    parser = argparse.ArgumentParser(description='生成本地节点配置文件')
    parser.add_argument('protocol', help='协议名称，例如 hbmpc、admpc 等')
    parser.add_argument('N',       type=int, help='节点总数 N')
    parser.add_argument('t',       type=int, help='最大容错数 t')
    parser.add_argument('layers',  type=int, help='电路层数')
    parser.add_argument('total_cm',type=int, help='乘法门总数 total_cm')
    parser.add_argument('--run-id', dest='run_id', default=None,
                        help='可选；设置 run_id，若不指定则随机生成')
    args = parser.parse_args()

    protocol = args.protocol.lower()
    N         = args.N
    t         = args.t
    layers    = args.layers
    total_cm  = args.total_cm
    run_id    = args.run_id or uuid.uuid4().hex

    # 参数校验
    if N < 3 * t + 1:
        raise ValueError(f"N={N} 必须满足 N >= 3*t+1")

    # 1) 全局 SRS
    srs_bytes   = lib.pyNewSRS(t)
    srs_encoded = base64.b64encode(srs_bytes).decode('utf-8')

    # 2) 决定是否按层拆分
    effective_layers = 1 if protocol == 'hbmpc' else layers

    # 3) 批量生成 TBLS / ACSS 密钥
    tbls_pub_layers  = []  # 每层的 TBLS 公钥（单个字符串）
    tbls_priv_layers = []  # 每层的 TBLS 私钥列表（长度 = N）
    acss_pk_layers   = []  # 每层的 ACSS 公钥列表（长度 = N）
    acss_sk_layers   = []  # 每层的 ACSS 私钥列表（长度 = N）
    for layer_idx in range(effective_layers):
        # TBLS（门限签名）密钥
        pub_key, priv_keys = generate_serialized_keys(N, t)
        tbls_pub_layers.append(pub_key)
        tbls_priv_layers.append(priv_keys)

        # ACSS（承诺分享）密钥
        pk_list, sk_list = acss_key_gen_with_srs(srs_bytes, N)
        acss_pk_layers.append(pk_list)
        acss_sk_layers.append(sk_list)

    # 4) 构造 peers 列表：16 个真实 IP + 从 7001 开始的端口代表层号
    ips = ["150.158.35.81",
    "124.220.16.71",
    "101.43.22.70",
	"111.229.197.238",
    "124.222.6.165",
    "1.116.108.22",
    "1.15.15.230",
	"111.229.40.140",
    "203.195.208.93",
    "106.53.26.38",
    "42.193.192.137",
	"43.139.185.179",
    "43.136.183.52",
    "148.70.214.61",
    "139.155.173.17",
	"1.14.63.87"
    ]
    if N > len(ips):
        raise ValueError(f"N={N} 超过了 IP 列表长度 {len(ips)}")

    base_port = 7001
    peers = []
    for layer_idx in range(effective_layers):
        port = base_port + layer_idx
        for ip in ips[:N]:
            peers.append(f"{ip}:{port}")

    # 5) 准备输出目录
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(script_dir, '..', 'conf',
                              f"{protocol}_{total_cm}_{layers}_{N}")
    os.makedirs(output_dir, exist_ok=True)

    # 6) 写入每个节点的配置文件
    for layer_idx in range(effective_layers):
        for node_id in range(N):
            my_send_id = layer_idx * N + node_id
            # 下一层的 ACSS 公钥列表（若最后一层则设为 ""）
            next_pk = (acss_pk_layers[layer_idx + 1][node_id]
                       if layer_idx + 1 < effective_layers else "")

            cfg = {
                "N":          N,
                "t":          t,
                "my_id":      node_id,
                "my_send_id": my_send_id,
                "layers":     layers,
                "total_cm":   total_cm,
                "peers":      peers,
                "extra": {
                    "run_id":        run_id,
                    "public_key":    tbls_pub_layers[layer_idx],
                    "private_key":   tbls_priv_layers[layer_idx][node_id],
                    "SRS":           srs_encoded,
                    "pks_acss":      acss_pk_layers[layer_idx][node_id],
                    "sk_acss":       acss_sk_layers[layer_idx][node_id],
                    "next_pks_acss": next_pk,
                }
            }

            file_path = os.path.join(output_dir, f"local.{my_send_id}.json")
            with open(file_path, 'w', encoding='utf-8') as fp:
                json.dump(cfg, fp, indent=4, ensure_ascii=False)
            print(f"✓ 已创建：{file_path}")


if __name__ == "__main__":
    main()