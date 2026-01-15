import json, os
        
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--N', metavar='N', required=True,
                        help='number of parties', type=int)
    
    parser.add_argument('--k', metavar='k', required=True,
                        help='batch size', type=int)

    parser.add_argument('--layers', metavar='layers', default=10,
                        help='number of circuit layers (default: 10)', type=int)
    

    args = parser.parse_args()
    
    N = args.N
    k = args.k
    layers = args.layers
    
    file_path = 'scripts/ip.txt'  

    with open(file_path, 'r') as file:
        ip_addresses = [line.strip() for line in file.readlines()[:N]]

    for i in range(N):
        # 这行是要运行本地测试的时候解除注释
        # port = 10001 + i * 200
        # 这行是要运行Dumbo-MPC真实环境的时候解除注释
        port = 7001
        ip_addresses[i] = f"{ip_addresses[i]}:{port}"
    
    for i in range(N):
        filename = f'conf/mpc_{N}/local.{i}.json'

        if not os.path.exists(filename):
            print(f"Error: {filename} does not exist.")
            continue

        if os.path.getsize(filename) == 0:
            print(f"Warning: {filename} is empty.")
            continue

        with open(filename, 'r') as json_file:
            try:
                data = json.load(json_file)
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON in {filename}: {e}")
                continue
        # 兜底：确保 extra 存在且是 dict
        if 'extra' not in data or not isinstance(data['extra'], dict):
            data['extra'] = {}

        data['extra']['k'] = k
        data['extra']['layers'] = layers
        data['peers'] = ip_addresses


        with open(filename, 'w') as json_file:
            json.dump(data, json_file, indent=4)
    
