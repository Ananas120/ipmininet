#!/usr/bin/env python3

from ipmininet.ipnet import IPNet
from ipmininet.cli import IPCLI
from ipmininet.iptopo import IPTopo
from ipmininet.router.config import BGP, OSPF, OSPF6, RouterConfig, AF_INET, AF_INET6, set_rr, bgp_fullmesh, ebgp_session, SHARE, CLIENT_PROVIDER, bgp_peering

families = (
    AF_INET(redistribute=('connected',)),
    AF_INET6(redistribute=('connected',))
)

class TestTopo(IPTopo):
    def build(self, * args, ** kwargs):
        def add_daemon(r):
            r.addDaemon(BGP, address_families=families)
            r.addDaemon(OSPF)
            r.addDaemon(OSPF6)
            return r
        
        as1_r1 = self.addRouter("as1_r1", config = RouterConfig)
        as2_r1 = self.addRouter("as2_r1", config = RouterConfig)
        
        as1_r2 = self.addRouter("as1_r2", config = RouterConfig)
        as2_r2 = self.addRouter("as2_r2", config = RouterConfig)
        
        as1_h = self.addHost("as1_h")
        as2_h = self.addHost("as2_h")
        
        self.addAS(1, [as1_r1, as1_r2])
        self.addAS(2, [as2_r1, as2_r2])
        
        add_daemon(as1_r1)
        add_daemon(as2_r1)
        
        add_daemon(as1_r2)
        add_daemon(as2_r2)
                
        self.addLink(as1_r2, as1_h)
        self.addLink(as1_r2, as1_r1)
        self.addLink(as1_r1, as2_r1)
        self.addLink(as2_r2, as2_r1)
        self.addLink(as2_r1, as2_h)
        
        set_rr(self, rr = as1_r1, peers = [as1_r2])
        set_rr(self, rr = as2_r1, peers = [as2_r2])
        ebgp_session(self, as1_r1, as2_r1, link_type=CLIENT_PROVIDER)
        
        super().build(*args, **kwargs)
        
        
if __name__ == '__main__':
    # allocate_IPS = False to disable IP auto-allocation
    net = IPNet(topo=TestTopo())
    try:
        net.start()
        IPCLI(net)
    finally:
        net.stop()
