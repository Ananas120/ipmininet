#!/usr/bin/env python3

import json
import itertools

from ipmininet.ipnet import IPNet
from ipmininet.cli import IPCLI
from ipmininet.iptopo import IPTopo
from ipmininet.router.config import BGP, OSPF, OSPF6, RouterConfig, AF_INET, AF_INET6, set_rr, bgp_fullmesh, ebgp_session, SHARE, CommunityList, AccessList, BGPRoute, BGPAttribute, ExaList, ExaBGPDaemon
from ipaddr_utils import format_prefixes, format_address, create_subnets
from ipaddress import ip_network

_link_types = {
    'share' : SHARE
}

def get_next_multiple(n, multiple):
    if n % multiple == 0: return n
    return (n // multiple + 1) * multiple



class JSONTopo(IPTopo):
    def __init__(self, filename, *args,
                 add_hosts = False,
                 infer_ip = False, infer_ip_lo = False, infer_ip_link = False,
                 name = 'Network Topology', debug = False,
                 ** kwargs
                ):
        self.name   = name
        self.debug  = debug
        self.filename = filename
        self.add_hosts  = add_hosts
        self.infer_ip_lo    = infer_ip_lo or infer_ip
        self.infer_ip_link  = infer_ip_link or infer_ip

        self.__as       = {}
        self.__routers  = {}
        self.__anycast  = {}
        self.__anycast_servers  = {}
        self.__hosts    = {}
        self.__links    = {}
        self.__subnets  = {}
        self.__prefixes = {}
        self.__bgp_sessions = {
            'fullmesh' : [],   # list de tuple / list (ensemble des rr dans le fullmesh)
            'clients' : {},     # RR_name : clients
            'ebgp' : {}         # AS : list (router - voisin)
        }
        self.__communities = {}

        self.exaBGPCounter = 0;
        
        super().__init__(self, * args, ** kwargs)
    
    @property
    def as_names(self):
        return list(self.__as.keys())
    
    @property
    def list_links(self):
        links = []
        for node, voisins in self.__links.items():
            config = {}
            if isinstance(voisins, dict):
                config = voisins
                voisins = config.pop('voisins', [])
            if not isinstance(voisins, (list, tuple)): voisins = [voisins]
                        
            for voisin in voisins:
                voisin_config = {}
                if isinstance(voisin, list):
                    voisin, voisin_config = voisin
                
                links.append([
                    node, voisin, {** config, ** voisin_config}
                ])
        
        return links
    
    @property
    def list_routers(self):
        return list(self.__routers.keys())
    
    @property
    def list_non_rr_routers(self):
        return [r_name for r_name in self.list_routers if r_name not in self.list_rr]
    
    @property
    def list_rr(self):
        liste = []
        for as_name, as_infos in self.__as.items():
            for nivea, rr in as_infos.get('rr', {}).items():
                liste += list(rr.keys())
        return liste
    
    @property
    def list_ibgp_sessions(self):
        links = []
        for rr, clients in self.__bgp_sessions['clients'].items():
            for c in clients:
                links.append([rr, c])
        
        for rr_groupe in self.__bgp_sessions['fullmesh']:
            for combinaison in itertools.combinations(rr_groupe, 2):
                links.append(list(combinaison))
        
        return links
    
    @property
    def list_ebgp_sessions(self):
        already_added = {}
        links = []
        for as_name, as_voisins in self.__bgp_sessions['ebgp'].items():
            for as_voisin, connections in as_voisins.items():
                for router_as1, router_as2, link_type in connections:
                    if router_as1 in already_added.get(router_as2, {}) or router_as2 in already_added.get(router_as1, {}):
                        continue
                    
                    links.append([router_as1, router_as2, link_type])
                    
                    already_added.setdefault(router_as1, [])
                    already_added[router_as1].append(router_as2)
                
        return links
    
    
    
    
    def __str__(self):
        des = '\n==============================\n'
        des += 'Description of {}\n'.format(self.name)
        des += '==============================\n\n'
        des += self.describe() + '\n'
        des += self.describe_ibpg() + '\n'
        des += self.describe_ebgp() + '\n'
        des += self.describe_anycast() + '\n'
        return des
    
    def describe(self):
        des = "Description générale :\n"
        des += "- ASes (number = {}) : {}\n".format(len(self.__as), self.as_names)
        
        des += "- Number of routers for each AS (total = {}) :\n".format(len(self.__routers))
        for as_name, as_infos in self.__as.items():
            if len(as_infos.get('routers', [])) > 0:
                   des += "-- Number of routers for AS {} \t: {}\n".format(as_name, len(as_infos.get('routers')))
            
        des += "- Number of hosts for each AS (total = {}) :\n".format(len(self.__hosts))
        for as_name, as_infos in self.__as.items():
            if len(as_infos.get('hosts', [])) > 0:
                   des += "-- Number of hosts for AS {} \t: {}\n".format(as_name, len(as_infos.get('hosts')))
                   
        des += "- Number of physical links : {}\n".format(len(self.list_links))
        des += "- Number of iBGP sessions : {}\n".format(len(self.list_ibgp_sessions))
        des += "- Number of eBGP sessions : {}\n".format(len(self.list_ebgp_sessions))
        return des
    
    def describe_ibpg(self):
        des = "Description of iBGP connections :\n"
        des += "- Number of iBGP sessions : {}\n".format(len(self.list_ibgp_sessions))
        for as_name, as_infos in self.__as.items():
            if len(as_infos.get('rr', {})) > 0:
                des += "- RR hierarchy for AS {} :\n".format(as_name)
            for rr_level, rr in sorted(
                list(as_infos.get('rr', {}).items()), 
                key = lambda infos: infos[0]
            ):
                des += "-- RR of level {} : {}\n".format(rr_level, list(rr.keys()))
        
        des += "- List of full-mesh :\n"
        for fullmesh in self.__bgp_sessions['fullmesh']:
            des += "-- {}\n".format(fullmesh)
        
        des += "- Number of non-RR router : {}\n".format(len(self.list_non_rr_routers))
        return des
    
    def describe_ebgp(self):
        des = "Description of eBGP sessions :\n"
        des += "- Number of eBGP sessions : {}\n".format(len(self.list_ebgp_sessions))
        return des
        
    def describe_anycast(self):
        if len(self.__anycast) == 0: return ''
        
        des = "Description of Anycast servers :\n"
        des += "- Number of Anycast addresses : {}\n".format(len(self.__anycast))
        
        for anycast_addr, nodes in self.__anycast.items():
            des += "-- Servers for anycast address {} :\n".format(anycast_addr)
            for router, server in nodes:
                des += "--- Server {} connected to {}\n".format(server, router)
                
        return des
        
    def get(self, name):
        if isinstance(name, (list, tuple)):
            return [self.get(n) for n in name]
        return self.__routers.get(
            name, self.__hosts.get(
                name, self.__anycast_servers.get(
                    name, None)))

    def get_routers(self, as_name = None):
        if as_name is None: return list(self.__routers.values())
        return self.get(self.__as[as_name]['routers'])
        
    def get_anycast_servers(self, as_name = None):
        if as_name is None: return list(self.__anycast_servers.values())
        return self.get(list(self.__as[as_name]['anycast_servers'].keys()))
        
    def get_hosts(self, as_name = None):
        if as_name is None: return list(self.__hosts.values())
        return self.get(self.__as[as_name]['hosts'])
    
    def get_as_of(self, name):
        for as_name, as_config in self.__as.items():
            if name in as_config['routers'] or name in as_config['hosts'] or name in as_config['anycast_servers']:
                return as_name
        return None
    
    def get_subnet_of(self, name):
        for subnet, subnet_config in self.__subnets.items():
            if name in subnet_config.get('nodes', []): return subnet
        return None
    
    def generate_ip(self, name, n = 1, host_bits = 0, ipv4 = True, ipv6 = True):
        def add_addr_to_subnet(net, first_addr, host_bits, is_ipv6):
            sep = '.' if not is_ipv6 else ':'
            new_mask = 32 - host_bits if not is_ipv6 else 128 - host_bits
            
            ip_subnet = format_address(net, self.__prefixes, is_ipv6 = is_ipv6)
            
            last_bits = ip_subnet.split('/')[0].split(sep)[-1]
            if is_ipv6: last_bits = 0 if last_bits == '' else int(last_bits, 16)
            else: last_bits = int(last_bits)
            last_bits += first_addr
            
            new_ip = ip_subnet.split('/')[0].split(sep)
            new_ip[-1] = str(last_bits)

            new_ip = sep.join(new_ip) + '/' + str(new_mask)
            
            return new_ip
        
        subnet = self.get_subnet_of(name)
        
        if subnet is None: return None
        
        self.__subnets[subnet].setdefault('nb_used_ip', 1)
        nb_used_ip = self.__subnets[subnet]['nb_used_ip']
        
        first_addr = get_next_multiple(nb_used_ip, 2 ** host_bits)
        self.__subnets[subnet]['nb_used_ip'] = first_addr + n
        
        new_subnet = []
        if ipv4:
            if 'ipv4' not in self.__subnets[subnet]:
                print("[WARNING]\tSubnet {} has not ipv4 address !".format(subnet))
            else:
                new_ipv4 = add_addr_to_subnet(
                    self.__subnets[subnet]['ipv4'], first_addr, host_bits, is_ipv6 = False
                )
                
                new_subnet.append(new_ipv4)
                
        if ipv6:
            if 'ipv6' not in self.__subnets[subnet]:
                print("[WARNING]\tSubnet {} has not ipv6 address !".format(subnet))
            else:
                new_ipv6 = add_addr_to_subnet(
                    self.__subnets[subnet]['ipv6'], first_addr, host_bits, is_ipv6 = True
                )
                if '::/' not in new_ipv6:
                    new_ipv6 = new_ipv6.replace(':/', '::/')
                
                new_subnet.append(new_ipv6)
        
        subnets = create_subnets(new_subnet, n = n)
        return subnets if len(subnets) > 1 else subnets[0]
            
    def add_new_link(self, r1, r2):
        if r1 in self.__links:
            if isinstance(self.__links[r1], dict):
                self.__links[r1].setdefault('nodes', [])
                self.__links[r1]['nodes'].append(r2)
            else:
                self.__links[r1].append(r2)
        else:
            self.__links[r1] = [r2]
        
    def add_fictif_host(self, as_name, r_name):
        if isinstance(self.add_hosts, bool):
            self.add_host_to_router(r_name, 1)
        elif isinstance(self.add_hosts, int):
            if len(self.__as[as_name].get('hosts', [])) < self.add_hosts:
                self.add_host_to_router(r_name, 1)
        elif isinstance(self.add_hosts, str):
            if as_name == self.add_hosts:
                self.add_host_to_router(r_name, 1)
        elif isinstance(self.add_hosts, list):
            if as_name in self.add_hosts:
                self.add_host_to_router(r_name, 1)
        elif isinstance(self.add_hosts, dict):
            if len(self.__as[as_name].get('hosts', [])) < self.add_hosts.get(as_name, 0):
                self.add_host_to_router(r_name, 1)
        else:
            self.add_host_to_router(r_name, 1)
    
    def add_bgp_fullmesh(self, niveau, rr):
        self.__bgp_sessions['fullmesh'].append(rr)
        if self.debug:
            print("Adding iBGP full-mesh between RR of level {} : {}".format(niveau, rr))
        return bgp_fullmesh(self, [self.__routers[copain_rr] for copain_rr in rr])
    
    def add_bgp_clients(self, rr_name, clients):
        self.__bgp_sessions['clients'][rr_name] = clients
        if self.debug: 
            print("Setting router {} as Route Reflector with clients {}".format(rr_name, clients))

        if len(clients) > 0:
            set_rr(self, rr = self.__routers[rr_name], peers = clients)
        return True
    
    def add_ebgp_session(self, node, voisin, as_1, as_2, link_type = 'share'):
        self.__bgp_sessions['ebgp'].setdefault(as_1, {})
        self.__bgp_sessions['ebgp'][as_1].setdefault(as_2, [])
        
        self.__bgp_sessions['ebgp'].setdefault(as_2, {})
        self.__bgp_sessions['ebgp'][as_2].setdefault(as_1, [])
        
        self.__bgp_sessions['ebgp'][as_1][as_2].append([node, voisin, link_type])
        self.__bgp_sessions['ebgp'][as_2][as_1].append([voisin, node, link_type])
        
        if self.debug:
            print("{} and {} have different AS ({} vs {}), creating an eBGP connection with {} link".format(node, voisin, as_1, as_2, link_type))
        
        return ebgp_session(self, node, voisin, link_type = None) #_link_types.get(link_type, None))
    
    def add_daemons(self, router, daemons, default_daemons = []):
        if isinstance(default_daemons, list):
            default_daemons = {d : {} for d in default_daemons}
        if isinstance(daemons, list): daemons = {d : {} for d in daemons}
        
        daemons = {** default_daemons, ** daemons}
        for d, d_config in daemons.items():
            if self.debug: print("Adding daemon {} with config {}".format(d, d_config))
            if d == 'ospf':
                router.addDaemon(OSPF)
            elif d == 'ospf6':
                router.addDaemon(OSPF6)
            elif d == 'bgp':
                if 'networks' in d_config:
                    d_config['networks'] = format_address(
                        d_config['networks'], self.__prefixes
                    )
                if 'communities' in d_config:
                    self.__communities[router] = d_config["communities"]

                families = (
                    AF_INET(redistribute=('connected',)),
                    AF_INET6(redistribute=('connected',))
                )
                router.addDaemon(BGP, address_families=families)
            elif d == "exaBGP":
                self.add_exaBGP(router, d_config)
            
        return True

    def add_exaBGP(self, router, config):
        #Creating a ExaBGP router to inject routes to router
        exa_routes = {
            "ipv4": [
                BGPRoute(ip_network(ip), [BGPAttribute("next-hop", "self"),
                                                BGPAttribute("as-path", ExaList([999,90])),
                                                BGPAttribute("med", 10),
                                                BGPAttribute("origin", "egp")]) for ip in config["ipv4"]
            ],
            "ipv6": [
                BGPRoute(ip_network(ip), [BGPAttribute("next-hop", "self"),
                                                BGPAttribute("as-path", ExaList([999,90])),
                                                BGPAttribute("med", 10),
                                                BGPAttribute("origin", "egp")]) for ip in config["ipv6"]
            ]
        }

        af4 = AF_INET(routes=exa_routes['ipv4'])
        af6 = AF_INET6(routes=exa_routes['ipv6'])

        # Add all routers
        exaBGPRouter = self.addRouter(router+"_exa", config=RouterConfig, use_v4=True, use_v6=True)
        exaBGPRouter.addDaemon(ExaBGPDaemon, address_families=(af4, af6))

        link = self.addLink(exaBGPRouter, router)
        link[exaBGPRouter].addParams(ip=("10.1.0.1/24", "fd00:12::1/64",))
        link[router].addParams(ip=("10.1.0.2/24", "fd00:12::2/64",))
        self.addAS(self.exaBGPCounter + 65000)
        self.exaBGPCounter +=1
        ebgp_session(self, router, exaBGPRouter)

    def add_link(self, node, voisin, config_node, config_voisin, link_type = 'share', 
                 ** kwargs):
        as_1, as_2 = self.get_as_of(node), self.get_as_of(voisin)
        node, voisin = self.get(node), self.get(voisin)
        
        config_node = config_node.copy()
        
        ip1, ip2 = config_node.pop('ip', None), config_voisin.pop('ip', None)
                                
        if 'subnet' in config_voisin:
            subnet = config_voisin.pop('subnet')
            if isinstance(subnet, dict):
                subnet = format_address(subnet, self.__prefixes)
            ip1, ip2 = subnet
        elif self.infer_ip_link:
            generated_ips = self.generate_ip(node, 2, 1)
            if generated_ips:
                ip1, ip2 = generated_ips
        
        kwargs = {** config_node, ** config_voisin}
        if ip1 is not None:
            kwargs.setdefault('params1', {})
            kwargs['params1']['ip'] = ip1
        if ip2 is not None:
            kwargs.setdefault('params2', {})
            kwargs['params2']['ip'] = ip2
            
        
        if self.debug:
            print("Adding link between {} and {} with config : {}".format(node, voisin, kwargs))
        
        link = self.addLink(node, voisin, ** kwargs)
        
        if as_1 != as_2:
            self.add_ebgp_session(node, voisin, as_1, as_2, link_type)
            
        return link
    
    def add_host_to_router(self, router, n = 1):
        as_name = self.get_as_of(router)
        for i in range(n):
            h_name = '{}_{}'.format(router, i)[-9:]
            
            if self.debug: print("Adding host {} to router {}".format(h_name, router))
            
            self.__as[as_name]['hosts'].append(h_name)
            self.__hosts[h_name] = self.addHost(h_name)
            
            # Add link between router and new host
            self.add_new_link(router, h_name)
            
            subnet = self.get_subnet_of(router)
            if subnet is not None:
                self.__subnets[subnet]['nodes'].append(h_name)
            
    
    def build(self, *args, **kwargs):
        with open(self.filename, 'r', encoding = 'utf-8') as file:
            config = file.read()
        config = json.loads(config)
        
        self.__links = config.get('links', {})
        self.__subnets = config.get('subnets', {})
        self.__prefixes = format_prefixes(config.get('subnets', {}))
        
        self._build_as(** config['AS'])
        self._build_bgp_communities()
        self._build_links()
        
        super().build(* args, ** kwargs)
    
    def _build_bgp_communities(self):
        for router in self.__communities:
            communities_config = self.__communities[router]
            all_al4 = AccessList(family='ipv4', name='allv4', entries=('any',))
            all_al6 = AccessList(family='ipv6', name='allv6', entries=('any',))

            if "set_local_pref" in communities_config:
                for community_value in communities_config["set_local_pref"]:
                    local_pref = communities_config["set_local_pref"][community_value]
                    
                    community = CommunityList("loc-pref", community=community_value)
                    for x in self.__routers:
                        router.get_config(BGP)\
                            .set_local_pref(local_pref,from_peer=x, matching=(community,), name="rm", order=10)\
                            .set_local_pref(100, from_peer=x, matching=(all_al4, all_al6,),name='rm', order=20)


            if "send_community" in communities_config:
                for community_value in communities_config["send_community"]:
                    for router_y in self.__routers:
                        router.get_config(BGP).set_community(community_value, to_peer=router_y, matching=(all_al4, all_al6))
        
    def _build_as(self, * args, ** ases):
        for i, (as_name, as_config) in enumerate(ases.items()):
            asn = as_config.get('ASN', i+1)
            if self.debug: print("Creating new AS : {} (ASN = {})".format(as_name, asn))
            self.__as[as_name] = {
                'routers' : [], 'hosts' : [], 'rr' : {}, 'anycast_servers' : {}
            }

            self._build_anycast_servers(
                as_name, as_config.get('anycast', []), as_config.get('routers', {})
            )
            self._build_routers(
                as_name, as_config.get('routers', {}), ** as_config.get('rconfig', {})
            )
            self._build_hosts(
                as_name, as_config.get('hosts', {}), ** as_config.get('hconfig', {})
            )
            
            if as_config.get('linked', False):
                for (r1, r2) in itertools.combinations(self.get_routers(as_name), 2):
                    self.add_new_link(r1, r2)

            
            self.addAS(asn, self.get_routers(as_name) + self.get_anycast_servers(as_name))
        
    def _build_routers(self, as_name, routers, ** default_config):
        default_daemons = default_config.pop('daemons', [])

        for r_name, r_config in routers.items():
            self.__as[as_name]['routers'].append(r_name)
                                    
            r_config = {** default_config, ** r_config}
            if 'lo_addresses' in r_config:
                # option lo_addresses = [IPV6_ADDRESS, IPV4_ADDRESS] to set the loopback address of the router
                # see https://ipmininet.readthedocs.io/en/latest/addressing.html
                r_config['lo_addresses'] = format_address(
                    r_config['lo_addresses'], self.__prefixes
                )
            elif self.infer_ip_lo:
                lo_addr = self.generate_ip(r_name, ipv4 = True, ipv6 = True)
                if lo_addr is not None:
                    r_config['lo_addresses'] = lo_addr
            
            
            r_kwargs = {k : v for k, v in r_config.items() if k in ('lo_addresses', )}
            
            if self.debug:
                print("Adding router {} to AS {} with config {}".format(r_name, as_name, r_kwargs))
            
            router = self.addRouter(r_name, config = RouterConfig, ** r_kwargs)
            self.add_daemons(router, r_config.get('daemons', []), default_daemons)
            
            self.__routers[r_name] = router
            
            if 'clients' in r_config or 'peers' in r_config:
                niv = r_config.get('niveau', 1)
                rr_config = {'niveau' : niv}
                if 'clients' in r_config: rr_config['clients'] = r_config['clients']
                if 'peers' in r_config: rr_config['peers'] = r_config['peers']
                
                self.__as[as_name]['rr'].setdefault(niv, {})
                self.__as[as_name]['rr'][niv][r_name] = rr_config
            
            if 'hosts' in r_config:
                self.add_host_to_router(r_name, r_config['hosts'])
            
            if self.add_hosts:
                self.add_fictif_host(as_name, r_name)
                            
        self._build_rr(as_name)
        
    def _build_rr(self, as_name):
        rr_hierarchy = self.__as[as_name]['rr']
        for niveau, rr in rr_hierarchy.items():
            if self.debug:
                print("Adding RR of level {} :".format(niveau))
            
            for i, (rr_name, rr_config) in enumerate(rr.items()):
                clients = self.get(rr_config.get('clients', []))

                self.add_bgp_clients(rr_name, clients)
                
                if niveau > 1 and 'peers' in rr_config:
                    copains_rr = [rr_name] + rr_config['peers']
                    self.add_bgp_fullmesh(niveau, copains_rr)
                    
            if niveau == 1:
                self.add_bgp_fullmesh(niveau, list(rr.keys()))
        
        
    def _build_anycast_servers(self, as_name, anycast, as_routers):
        rr_levels = []
        for r_name, r_config in as_routers.items():
            rr_levels.append(r_config.get('niveau', 1) if 'clients' in r_config or 'peers' in r_config else 0)
        anycast_rr_level = max(rr_levels) + 1
        
        for anycast_config in anycast:
            anycast_address = anycast_config['addresses']
            anycast_address = tuple(format_address(anycast_address, self.__prefixes))
            
            self.__anycast.setdefault(anycast_address, [])
            
            if self.debug:
                print("Adding anycast address : {}".format(anycast_address))
            
            for node in anycast_config.get('nodes', []):
                server_name = 'server_{}'.format(len(self.__anycast_servers) + 1)
                self.__as[as_name]['anycast_servers'][server_name] = anycast_address
                self.__anycast[anycast_address].append((node, server_name))
                
                s_config = {'lo_addresses' : anycast_address}
            
                if self.debug:
                    print("Adding server {} to this anycast address".format(server_name))
            
                server = self.addRouter(server_name, config = RouterConfig, ** s_config)
                self.add_daemons(
                    server, {'bgp' : anycast_config.get('bgp_config', {})}, {}
                )

                self.__anycast_servers[server_name] = server
                
                self.add_new_link(server_name, node)
                
                # Add the node to the clients of the router
                if 'clients' not in as_routers[node] and 'peers' not in as_routers[node]:
                    as_routers[node].setdefault('niveau', anycast_rr_level)
                as_routers[node].setdefault('clients', [])
                as_routers[node]['clients'].append(server_name)
            
                subnet = self.get_subnet_of(node)
                if subnet is not None:
                    self.__subnets[subnet]['nodes'].append(server_name)
        
    def _build_hosts(self, as_name, hosts, ** default_config):
        for h_name, h_config in hosts.items():
            if self.debug: print("Adding host {}".format(h_name))
            self.__as[as_name]['hosts'].append(h_name)
            self.__hosts[h_name] = self.addHost(h_name, ** {** default_config, ** h_config})
            
    def _build_links(self):
        for node, voisins in self.__links.items():
            config = {}
            if isinstance(voisins, dict):
                config = voisins
                voisins = config.pop('voisins', [])
            if not isinstance(voisins, (list, tuple)): voisins = [voisins]
                        
            for voisin in voisins:
                voisin_config = {}
                if isinstance(voisin, list):
                    voisin, voisin_config = voisin
                
                link_type = voisin_config.pop('link_type', 'share')
                
                self.add_link(node, voisin, config, voisin_config, link_type)
        
    def __getattr__(self, item):
        if not item.startswith('add'):
            return self.__getattribute__(item)
        return super().__getattr__(item)
    
if __name__ == '__main__':
    # allocate_IPS = False to disable IP auto-allocation
    topo = JSONTopo(
        filename = 'topo_ovh.json', debug = True, name = 'OVH East-Europa topology',
        add_hosts = True, infer_ip = True
    )
    net = IPNet(topo=topo, allocate_IPs = True)
    print(topo)
    try:
        net.start()
        IPCLI(net)
    finally:
        net.stop()
