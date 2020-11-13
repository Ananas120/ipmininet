#!/usr/bin/env python3

from ipmininet.ipnet import IPNet
from ipmininet.cli import IPCLI
from ipmininet.iptopo import IPTopo
from ipmininet.router.config import BGP, OSPF, OSPF6, RouterConfig, AF_INET, AF_INET6, set_rr, bgp_fullmesh, ebgp_session, SHARE, CLIENT_PROVIDER, bgp_peering
from ipmininet.host.config import Named, ARecord, AAAARecord, PTRRecord

families = (
    AF_INET(redistribute=('connected',)),
    AF_INET6(redistribute=('connected',))
)

class AnycastTopo(IPTopo):
    def build(self, * args, ** kwargs):
        def add_daemon(* routers):
            for r in routers:
                r.addDaemon(BGP, address_families=families, ** kwargs)
                r.addDaemon(OSPF)
                r.addDaemon(OSPF6)
            return routers
        
        server_ip = ["10.10.10.10", "10::10"]
        
        """ Routers """
        as1_r1, as1_r2, as1_rr = self.addRouters("as1_r1", "as1_r2", "as1_rr")
        
        as2_r1 = self.addRouter("as2_r1", config = RouterConfig)
        
        """ Hosts """
        as1_h1, as1_h2 = [self.addHost(n) for n in ("as1_h1", "as1_h2")]
        as2_h = self.addHost("as2_h")
        
        """ Servers """
        
        master = self.addHost("master")
        serv1 = self.addHost("s1")
        serv2 = self.addHost("s2")
        
        """ AS """
        
        self.addAS(1, [as1_r1, as1_r2, as1_rr])
        self.addAS(2, [as2_r1])
        
        """ Daemons """
        serv1.addDaemon(Named)
        serv2.addDaemon(Named)
        
        records = [
            ARecord(serv1, server_ip[0], ttl=240), AAAARecord(serv1, server_ip[1])
        ]
        self.addDNSZone(name="group10", dns_master=master,
                        dns_slaves=[], nodes=[serv2, serv1],
                        )
        
        #add_daemon(serv1, serv2)
        
        add_daemon(as1_r1, as1_r2, as1_rr)
        
        add_daemon(as2_r1)
        
        """ Links """
        
        self.addLinks((as1_r1, serv1), (as1_r2, serv2))
        
        self.addLink(as1_r1, master)
        
        self.addLink(as1_rr, as1_r1, igp_metric = 2)
        self.addLinks((as1_rr, as1_r2), (as1_rr, as2_r1))
        self.addLinks((as1_r1, as1_h1), (as1_rr, as1_h2), (as2_r1, as2_h))
                
        set_rr(self, rr = as1_rr, peers = [as1_r1, as1_r2])

        ebgp_session(self, as1_rr, as2_r1, link_type=SHARE)
        
        super().build(*args, **kwargs)
        
        
if __name__ == '__main__':
    # allocate_IPS = False to disable IP auto-allocation
    net = IPNet(topo=AnycastTopo())
    #print(type(net.get('as2_h')))
    s1 = net.get('s1')
    s2 = net.get('s2')
    #print(type(h))
    #print(help(h.setIP))
    #print(help(h))
    try:
        net.start()
        IPCLI(net)
    finally:
        net.stop()
