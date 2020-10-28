#!/usr/bin/env python3

from ipmininet.ipnet import IPNet
from ipmininet.cli import IPCLI
from ipmininet.iptopo import IPTopo
from ipmininet.router.config import BGP, OSPF, OSPF6, RouterConfig, AF_INET6, set_rr, bgp_fullmesh, ebgp_session, SHARE


class TestTopo(IPTopo):
    def build(self, * args, ** kwargs):
        as1_r1 = self.addRouter("as1_r1", config = RouterConfig)
        as2_r1 = self.addRouter("as2_r1", config = RouterConfig)
        
        as1_h = self.addHost("as1_h")
        as2_h = self.addHost("as2_h")
        
        self.addAS(1, nodes = ["as1_r1"])
        self.addAS(2, nodes = ["as2_r1"])
        
        as1_r1.addDaemon(BGP, address_families=[AF_INET6(redistribute=['connected'])])
        as2_r1.addDaemon(BGP, address_families=[AF_INET6(redistribute=['connected'])])
        
        as1_r1.addDaemon(OSPF)
        as2_r1.addDaemon(OSPF)
        
        as1_r1.addDaemon(OSPF6)
        as2_r1.addDaemon(OSPF6)
        
        self.addLink(as1_r1, as1_h)
        self.addLink(as1_r1, as2_r1)
        self.addLink(as2_r1, as2_h)
        
        ebgp_session(self, as1_r1, as2_r1)
        
        super().build(*args, **kwargs)
        
        
if __name__ == '__main__':
    # allocate_IPS = False to disable IP auto-allocation
    net = IPNet(topo=TestTopo())
    try:
        net.start()
        IPCLI(net)
    finally:
        net.stop()
