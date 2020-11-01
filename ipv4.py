def get_IPv4(cluster_name, router, interface, extern=False):
    if (router > 4 or interface > 8):
        raise Exception("Invalid IP, cluster:{}, router:{}, interface:{}".format(cluster, router, interface))
    
    if(cluster_name == "sin"):
        cluster = 1
    elif(cluster_name == "syd"):
        cluster = 2
    elif(cluster_name == "mrs"):
        cluster = 3
    elif(cluster_name == "sjo"):
        cluster = 4
    elif(cluster_name == "lax"):
        cluster = 5
    else:
        e = "Invalide cluster {}".format(cluster_name)
        raise Exception(e)
    
    suff = (cluster-1)*32+(router-1)*8+interface-1
    equip = 198
    if extern:
        equip = 199
    return "109.107.{}.{}/32".format(equip, suff)

def get_external_IPv4(AS_name, interface):
    if(AS_name == "equinix"):
        AS = 2
    elif(AS_name == "vodafone"):
        AS = 3
    elif(AS_name == "ntt"):
        AS = 4
    elif(AS_name == "telstra"):
        AS = 5
    elif(AS_name == "france-IX"):
        AS = 6
    elif(AS_name == "level3"):
        AS = 7
    elif(AS_name == "softbank"):
        AS = 8
    else:
        raise Exception("Invalide AS name: {}".format(AS_name))
    
    return "198.162.{}.{}/32".format(AS, interface-1)

def get_router(ip):
    type = "Internal"
    external = not int(ip.split('.')[-2]) % 2 == 0
    
    if external: #External 
        type = "External"
        
    for i in range(1, 9):
        for j in range(1, 5):
            for k in range(1, 9):
                ip_finded, ip_bin = get_IPv4(i, j, k, external)
                if ip == ip_finded:
                   return type, i, j, k
    raise Exception("Invalid IP; ip:{}".format(ip))