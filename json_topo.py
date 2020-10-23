#!/usr/bin/env python3

import json

from ipmininet.ipnet import IPNet
from ipmininet.cli import IPCLI
from ipmininet.iptopo import IPTopo
from ipmininet.router.config import BGP, OSPF, OSPF6, RouterConfig, AF_INET6, set_rr, bgp_fullmesh, ebgp_session, SHARE

from ipaddr_utils import format_prefixes, format_address, create_subnets

_link_types = {
    'share' : SHARE
}

class JSONTopo(IPTopo):
    def __init__(self, filename = 'topo.json', debug = False, *args, ** kwargs):
        self.debug = debug
        self.filename = filename
        self.__as       = {}
        self.__routers  = {}
        self.__hosts    = {}
        self.__links    = {}
        self.__subnets  = {}
        self.__prefixes = {}
        super().__init__(self, * args, ** kwargs)
        
    def get(self, name):
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
                        d_config['networks', self.__prefixes]
                    )
                
                family = AF_INET6(** d_config)
                router.addDaemon(BGP, address_families=(family,))
            
        return True
    
    def build(self, *args, **kwargs):
        with open(self.filename, 'r', encoding = 'utf-8') as file:
            config = file.read()
        config = json.loads(config)
        
        self.__subnets = config.get('subnets', {})
        self.__prefixes = format_prefixes(config.get('subnets', {}))
        
        self._build_as(** config['AS'])
        self._build_links(** config.get('links', {}))
        self._build_subnets(** config.get('subnets', {}))
        
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
            
            self.__routers[r_name] = router
        
        self._build_rr(as_name)
        
    def _build_rr(self, as_name):
        rr_hierarchy = self.__as[as_name]['rr']
        for niveau, rr in rr_hierarchy.items():
            if self.debug:
                print("Adding RR of level {} :".format(niveau))
            
            for i, (rr_name, rr_config) in enumerate(rr.items()):
                clients = [self.__routers[r_name] for r_name in rr_config.get('clients', [])]
                if self.debug: 
                    print("Setting router {} as Route Reflector with clients {}".format(rr_name, clients))

                if len(clients) > 0:
                    set_rr(self, rr = self.__routers[rr_name], peers = clients)

            copains_rr = rr_config.get('peers', list(rr.keys()))
            if self.debug:
                print("Set fullmesh between RR : {}".format(copains_rr))
            bgp_fullmesh(self, [self.__routers[copain_rr] for copain_rr in copains_rr])
        
        
    def _build_hosts(self, as_name, hosts, ** default_config):
        for h_name, h_config in hosts.items():
            if self.debug: print("Adding host {}".format(h_name))
            self.__as[as_name]['hosts'].append(h_name)
            self.__hosts[h_name] = self.addHost(h_name, ** {** default_config, ** h_config})
            
    def _build_links(self, ** links):
        self.__links = links
        for node, voisins in links.items():
            as_1 = self.get_as_of(node)
            node = self.get(node)
            
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
                
                as_2 = self.get_as_of(voisin)
                voisin = self.get(voisin)
                
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
                
                if self.debug:
                    print("Adding link between {} and {} with config : {}".format(node, voisin, link_kwargs))
                
                link = self.addLink(node, voisin, ** link_kwargs)
                
                if as_1 != as_2:
                    if self.debug:
                        print("{} and {} have different AS ({} vs {}), creating an eBGP connection with {} link".format(node, voisin, as_1, as_2, link_type))
                    
                    ebgp_session(self, node, voisin, link_type = _link_types[link_type])
        
    def _build_subnets(self, ** subnets):        
        for subnet_name, subnet_config in subnets.items():
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
        if item.startswith('_JSONTopo__'):
            print(self.__dict__.keys())
            return self.__dict__[item]
        return super().__getattr__(item)
    
if __name__ == '__main__':
    # allocate_IPS = False to disable IP auto-allocation
    net = IPNet(topo=JSONTopo('topo_ovh.json', debug = True))
    print(net)
    try:
        net.start()
        IPCLI(net)
    finally:
        net.stop()
