#!/usr/bin/env python3

from ipmininet.ipnet import IPNet
from ipmininet.cli import IPCLI
from ipmininet.iptopo import IPTopo
from ipmininet.router.config import BGP, OSPF, OSPF6, RouterConfig, AF_INET, AF_INET6, set_rr, bgp_fullmesh, ebgp_session, SHARE, CLIENT_PROVIDER, bgp_peering, Rule, IPTables, IP6Tables, InputFilter, Deny
from ipmininet.host.config import HostConfig

families = (
    AF_INET(redistribute=('connected',)),
    AF_INET6(redistribute=('connected',))
)

class SecurityTopo(IPTopo):
    """
        Basic Anycast topology. 
        
        Structure : 
        
          AS 2          |                   AS 1
                        |
                        |       +---------+
                        |       | as1_h1  |
                        |       +----+----+
                        |            |
                        |            |
        +-------+       |       +----+----+     +--------+
        | as2_h |       |       | as1_r1  +-----+   s1   |
        +---+---+       |       +----+----+     +--------+
            |           |            | 2
            |           |            |
       +----+---+       |       +----+----+     +--------+
       | as2_r1 +---------------+ as1_rr  +-----+ as1_h2 |
       +--------+       |       +----+----+     +--------+
                        |            |
                        |            |
                        |       +----+----+     +--------+
                        |       | as1_r2  +-----+   s2   |
                        |       +---------+     +--------+
                        
        Description : 
        - 2 AS, 4 routers, 1 RR, 2 "anycast servers", 3 hosts
        - as1_rr : Route-Reflector with [as1_r1, as1_r2] as clients. 
        - s1, s2 : anycast servers with same loop-back address :
            - IPv4 : 10.10.10.10/32
            - IPv6 : 10::10/128
        
        Tests and results : 
        - s1 ifconfig : shows well the 10::10 as loopback with global scpe but doesn't show the 10.10.10.10 address (but this address is still reachable on this server). 
        - ping6all : works
        - as1_h2 traceroute 10.10.10.10 : works and goes well to s2
        - as1_h2 traceroute 10::10 : works but in the raceroute, the path is "as1_r1 -> s2" but s2 is not connected to as1_r1 so i suppose it'es an error in the name
        - as2_h traceroute 10::10 : doesn't work (goes to as2_r1 and stops), idem for theIPv4 address (10.10.10.10). 
        - s1 and s2 must be routers because daemons (OSPF, OSPF6and BGP) are not available on hosts. 
        
        Security point of view :
	 3 things :  create the ip rules 
                     add the iptables daemon
                     set the ttl of routers with an eBGP connection to 255
    """
    def build(self, * args, ** kwargs):
        def add_daemon(* routers, ospf = True, bgp = True):
            for r in routers:
                if bgp:
                    r.addDaemon(BGP, address_families=families, ** kwargs)
                if ospf:
                    r.addDaemon(OSPF)
                    r.addDaemon(OSPF6)
            return routers
        
        server_ip = ["10.10.10.10/32", "10::10/128"]
        
        # vérifier que les paquets sur le port de bgp respectent le ttl
        #ip_rule = [InputFilter(default="DROP", rules=[
        #                Deny(proto='tcp', dport='179', match='ttl --ttl-lt 255')])]
        ip6_rule = [Rule('-A INPUT -p tcp --dport 179 -m hl --hl-lt 255 -j DROP')]
        
        """ Routers """
        as1_r1, as1_r2, as1_rr = self.addRouters("as1_r1", "as1_r2", "as1_rr")
        
        as2_r1 = self.addRouter("as2_r1", config = RouterConfig)
        
        """ Hosts """
        as1_h1, as1_h2 = [self.addHost(n) for n in ("as1_h1", "as1_h2")]
        as2_h = self.addHost("as2_h")
        
        """ Servers """
        
        serv1 = self.addRouter("s1", lo_addresses = server_ip)
        serv2 = self.addRouter("s2", lo_addresses = server_ip)
        
        """ AS """
        
        self.addAS(1, [as1_r1, as1_r2, as1_rr, serv1, serv2])
        self.addAS(2, [as2_r1])
        
        """ Daemons """
        add_daemon(serv1, serv2, ospf = False)
        
        add_daemon(as1_r1, as1_r2, as1_rr)
        
        add_daemon(as2_r1)
        
        # we add the ip_rule to the router of our AS that is connected to the other AS
        #as1_rr.addDaemon(IPTables, rules = ip_rule)
        as1_rr.addDaemon(IP6Tables, rules = ip6_rule)
        
        """ Links """
        
        self.addLinks((as1_r1, serv1), (as1_r2, serv2))
        
        self.addLink(as1_rr, as1_r1, igp_metric = 2)
        self.addLinks((as1_rr, as1_r2), (as1_rr, as2_r1))
        self.addLinks((as1_r1, as1_h1), (as1_rr, as1_h2), (as2_r1, as2_h))
                
        set_rr(self, rr = as1_rr, peers = [as1_r1, as1_r2])
        set_rr(self, rr = as1_r1, peers = [serv1])
        set_rr(self, rr = as1_r2, peers = [serv2])

        ebgp_session(self, as1_rr, as2_r1, link_type=None)

        super().build(*args, **kwargs)
        
	
        
if __name__ == '__main__':
    # allocate_IPS = False to disable IP auto-allocation
    net = IPNet(topo=SecurityTopo())
    #print(type(net.get('as2_h')))
    #s1 = net.get('s1')
    #s2 = net.get('s2')
    #print(type(h))
    #print(help(h.setIP))
    #print(help(h))
    net.get('as1_rr').cmd('sudo sysctl net.ipv4.ip_default_ttl=255')
    try:
        net.start()
        IPCLI(net)
    finally:
        net.stop()
