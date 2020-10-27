def is_ipv6(addr):
    return ':' in addr
    
def split_addr(address):
    ipv6 = is_ipv6(address)
    sep = ':' if ipv6 else '.'
    
    parts = []
    for p in address.split(sep):
        int_part = 0
        if len(p) > 0:
            int_part = int(p, 16 if ipv6 else 10)
        parts.append(int_part)
    return ipv6, parts

def build_addr(parts, is_ipv6):
    if not is_ipv6:
        return '.'.join([str(p) for p in parts])
    str_parts = []
    for p in parts:
        str_p = '' if p == 0 else hex(p)[2:]
        str_parts.append(str_p)
    
    return ':'.join(str_parts)

def format_prefixes(subnets):
    return {
        'ipv4' : {
            name : config.get('ipv4', '/0').split('/')[0]
            for name, config in subnets.items()
        },
        'ipv6' : {
            name : config.get('ipv6', '/0').split('/')[0]
            for name, config in subnets.items()
        }
    }

def format_address(address_config, prefixes, is_ipv6 = None):
    addresses = []
    if isinstance(address_config, str):
        assert is_ipv6 is not None
        if is_ipv6:
            return address_config.format(** prefixes.get('ipv6', {}))
        return address_config.format(** prefixes.get('ipv4', {}))
    elif isinstance(address_config, dict):
        if 'ipv4' in address_config:
            addresses.append(address_config['ipv4'].format(** prefixes.get('ipv4', {})))
        if 'ipv6' in address_config:
            addresses.append(address_config['ipv6'].format(** prefixes.get('ipv6', {})))
    
    return addresses

def create_subnets(subnet, n = 2):
    if not isinstance(subnet, (list, tuple)): subnet = [subnet]
    subnets = [[] for _ in range(n)]
    for sub in subnet:
        addr, mask_length = sub.split('/')
        is_ipv6, addr_part = split_addr(addr)
        
        addr_host = 128 - int(mask_length) if is_ipv6 else 32 - int(mask_length)
        max_addr = 2 ** addr_host
        if n > max_addr:
            raise ValueError("You want to create {} subnets with a mask of /{} which allows only {} subnets".format(n, mask_length, max_addr))
        
        for i in range(n):
            new_addr = addr_part[:-1] + [addr_part[-1] + i]
            new_addr = build_addr(new_addr, is_ipv6) + '/' + mask_length
            subnets[i].append(new_addr)
    return subnets
