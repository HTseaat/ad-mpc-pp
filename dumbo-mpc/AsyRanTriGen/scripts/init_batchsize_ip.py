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
    parser.add_argument(
        '--dumbo_mode',
        metavar='dumbo_mode',
        default='full',
        choices=['full', 'drop-epoch4', 'fault-accumulation'],
        help='dumbo_mpc_dyn mode: full | drop-epoch4 | fault-accumulation',
        type=str,
    )
    args = parser.parse_args()
    
    N = args.N
    k = args.k
    layers = args.layers
    dumbo_mode = args.dumbo_mode
    
    
    file_path = 'scripts/ip.txt'  
    if os.getenv('DUMBO_LOCAL_USE_IP_FILE') == '1':
        with open(file_path, 'r') as file:
            base_ips = [line.strip() for line in file.readlines()[:N]]
    else:
        base_ips = ['127.0.0.1'] * N

    ip_addresses = []
    for i in range(N):
        port = 10001 + i * 200
        ip_addresses.append(f"{base_ips[i]}:{port}")
    
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

        if 'extra' not in data or not isinstance(data['extra'], dict):
            data['extra'] = {}
        data['extra']['k'] = k
        data['extra']['layers'] = layers
        data['extra']['dumbo_mode'] = dumbo_mode
        data['peers'] = ip_addresses


        with open(filename, 'w') as json_file:
            json.dump(data, json_file, indent=4)
