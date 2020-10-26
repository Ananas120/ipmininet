#!/usr/bin/env python3

import json
import itertools

from ipmininet.ipnet import IPNet
from ipmininet.cli import IPCLI
from ipmininet.iptopo import IPTopo
from ipmininet.router.config import BGP, OSPF, OSPF6, RouterConfig, AF_INET6, set_rr, bgp_fullmesh, ebgp_session, SHARE

from ipaddr_utils import format_prefixes, format_address, create_subnets

_link_types = {
    'share' : SHARE
}

class JSONTopo(IPTopo):
    def __init__(self, filename = 'topo.json', debug = False, *args,
                 add_hosts = False, name = 'Network Topology', ** kwargs):
        self.name   = name
        self.debug  = debug
        self.filename = filename
        self.add_hosts  = add_hosts
        self.__as       = {}
        self.__routers  = {}
        self.__hosts    = {}
        self.__links    = {}
        self.__subnets  = {}
        self.__prefixes = {}
        self.__bgp_sessions = {
            'fullmesh' : [],   # list de tuple / list (ensemble des rr dans le fullmesh)
            'clients' : {},     # RR_name : clients
            'ebgp' : {}         # AS : list (router - voisin)
        }
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
        des += "- Number of iBGP sessions : {}\n".format(len(self.list_ebgp_sessions))
        return des
        
    def get(self, name):
        if isinstance(name, (list, tuple)):
            return [self.get(n) for n in name]
        return self.__routers.get(name, self.__hosts.get(name, None))

    def get_routers(self, as_name = None):
        if as_name is None: return list(self.__routers.values())
        return [self.__routers[r_name] for r_name in self.__as[as_name]['routers']]
        
    def get_hosts(self, as_name = None):
        if as_name is None: return list(self.__hosts.values())
        return [self.__hosts[r_name] for r_name in self.__as[as_name]['hosts']]
    
    def get_as_of(self, name):
        for as_name, as_config in self.__as.items():
            if name in as_config['routers'] or name in as_config['hosts']: return as_name
        return None
    
    def get_subnet_of(self, name):
        for subnet, subnet_config in self.__subnets.items():
            if name in subnet_config.get('nodes', []): return subnet
        return None
    
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
        
        return ebgp_session(self, node, voisin, link_type = _link_types.get(link_type, None))
    
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
                
                family = AF_INET6(** d_config)
                router.addDaemon(BGP, address_families=(family,))
            
        return True
    
    def add_link(self, node, voisin, link_type = 'share', ** kwargs):
        as_1 = self.get_as_of(node)
        as_2 = self.get_as_of(voisin)
        
        node = self.get(node)
        voisin = self.get(voisin)
        
        if self.debug:
            print("Adding link between {} and {} with config : {}".format(node, voisin, kwargs))
                
        link = self.addLink(node, voisin, ** kwargs)
        
        if as_1 != as_2:
            self.add_ebgp_session(node, voisin, as_1, as_2, link_type)
            
        return link
    
    def add_host_to_router(self, router, n = 1):
        as_name = self.get_as_of(router)
        for i in range(n):
            h_name = 'h{}_{}'.format(i, router)[:9]
            
            if self.debug: print("Adding host {} to router {}".format(h_name, router))
            
            self.__as[as_name]['hosts'].append(h_name)
            self.__hosts[h_name] = self.addHost(h_name)
            
            # Add link between router and new host
            if router in self.__links:
                if isinstance(self.__links[router], dict):
                    self.__links[router].setdefault('nodes', [])
                    self.__links[router]['nodes'].append(h_name)
                else:
                    self.__links[router].append(h_name)
            else:
                self.__links[router] = [h_name]
            
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
        self._build_links()
        self._build_subnets()
        
        super().build(* args, ** kwargs)
        
    def _build_as(self, * args, ** ases):
        for i, (as_name, as_config) in enumerate(ases.items()):
            if self.debug: print("Creating new AS : {}".format(as_name))
            self.__as[as_name] = {'routers' : [], 'hosts' : [], 'rr' : {}}

            self._build_routers(
                as_name, as_config.get('routers', {}), ** as_config.get('rconfig', {})
            )
            self._build_hosts(
                as_name, as_config.get('hosts', {}), ** as_config.get('hconfig', {})
            )
            
            self.addAS(i, self.get_routers(as_name))
        
    def _build_routers(self, as_name, routers, ** default_config):
        default_daemons = default_config.pop('daemons', [])

        for r_name, r_config in routers.items():
            self.__as[as_name]['routers'].append(r_name)
            
            if self.debug:
                print("Adding router {} to AS {}".format(r_name, as_name))
                        
            r_config = {** default_config, ** r_config}
            if 'lo_addresses' in r_config:
                # option lo_addresses = [IPV6_ADDRESS, IPV4_ADDRESS] to set the loopback address of the router
                # see https://ipmininet.readthedocs.io/en/latest/addressing.html
                r_config['lo_addresses'] = format_address(
                    r_config['lo_addresses'], self.__prefixes
                )
            
            r_kwargs = {k : v for k, v in r_config.items() if k in ('lo_addresses', )}
            router = self.addRouter(r_name, config = RouterConfig, ** r_kwargs)
            self.add_daemons(router, r_config.get('daemons', []), default_daemons)
            
            if 'clients' in r_config:
                niv = r_config.get('niveau', '1')
                rr_config = {'niveau' : niv}
                if 'clients' in r_config: rr_config['clients'] = r_config['clients']
                if 'peers' in r_config: rr_config['peers'] = r_config['peers']
                    
                self.__as[as_name]['rr'].setdefault(niv, {})
                self.__as[as_name]['rr'][niv][r_name] = rr_config
            
            if 'hosts' in r_config:
                self.add_host_to_router(r_name, r_config['hosts'])
            if self.add_hosts:
                if isinstance(self.add_hosts, int):
                    if len(self.__as[as_name].get('hosts', [])) < self.add_hosts:
                        self.add_host_to_router(r_name, 1)
                elif isinstance(self.add_hosts, str):
                    if as_name == self.add_hosts:
                        self.add_host_to_router(r_name, 1)
                else:
                    self.add_host_to_router(r_name, 1)
                    
            self.__routers[r_name] = router
        
        self._build_rr(as_name)
        
    def _build_rr(self, as_name):
        rr_hierarchy = self.__as[as_name]['rr']
        for niveau, rr in rr_hierarchy.items():
            if self.debug:
                print("Adding RR of level {} :".format(niveau))
            
            for i, (rr_name, rr_config) in enumerate(rr.items()):
                clients = [self.__routers[r_name] for r_name in rr_config.get('clients', [])]

                self.add_bgp_clients(rr_name, clients)
                
                if niveau > 1 and 'peers' in rr_config:
                    copains_rr = [rr_name] + rr_config['peers']
                    self.add_bgp_fullmesh(niveau, copains_rr)
                    
            if niveau == 1:
                self.add_bgp_fullmesh(niveau, list(rr.keys()))
        
        
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
            
            ip1 = None
            if 'ip' in config:
                ip1 = format_address(config.pop('ip'), self.__prefixes)
            
            for voisin in voisins:
                voisin_config = {}
                if isinstance(voisin, list):
                    voisin, voisin_config = voisin
                
                link_type = voisin_config.pop('link_type', 'share')
                
                ip2 = None
                if 'ip' in voisin_config:
                    ip2 = format_address(
                        voisin_config.pop('ip'), self.__prefixes
                    )
                
                link_kwargs = {** config, ** voisin_config}
                if ip1:
                    link_kwargs.setdefault('param1', {})
                    link_kwargs['param1']['ip'] = ip1
                if ip2:
                    link_kwargs.setdefault('param2', {})
                    link_kwargs['param2']['i2'] = ip2
                if 'subnet' in link_kwargs:
                    link_kwargs.setdefault('param1', {})
                    link_kwargs.setdefault('param2', {})
                    
                    subnet = link_kwargs.pop('subnet')
                    subnet = _parse_address(subnet, self.__prefixes)
                    subnet_1, subnet_2 = create_subnets(subnet)
                    
                    link_kwargs['param1']['ip'] = subnet_1
                    link_kwargs['param2']['ip'] = subnet_1

                self.add_link(node, voisin, ** link_kwargs)
        
    def _build_subnets(self):        
        for subnet_name, subnet_config in self.__subnets.items():
            if self.debug:
                print("Creating subnet {} with prefix :\n- IPv4 : {}\n- IPv6 : {}".format(
                    subnet_name, 
                    subnet_config.get('ipv4', None), 
                    subnet_config.get('ipv6', None)
                ))
            
            addresses = format_address(subnet_config, self.__prefixes)
            
            nodes = [self.get(node_name) for node_name in subnet_config.get('nodes', [])]
            
            if len(nodes) > 0:
                if self.debug:
                    print("Adding nodes {} to subnet".format(nodes))
                self.addSubnet(nodes, subnets = addresses)
            elif self.debug:
                print("No node attached to this subnet")

    def __getattr__(self, item):
        if not item.startswith('add'):
            return self.__getattribute__(item)
        return super().__getattr__(item)
    
if __name__ == '__main__':
    # allocate_IPS = False to disable IP auto-allocation
    topo = JSONTopo(
        filename = 'topo_ovh.json', debug = True, name = 'OVH Est-Europa topology',
        add_hosts = 1
    )
    net = IPNet(topo=topo)
    print(topo)
    try:
        net.start()
        IPCLI(net)
    finally:
        net.stop()
