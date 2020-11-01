from ipmininet.iptopo import IPTopo
from ipmininet.router.config import BorderRouterConfig, BGP, ebgp_session, RouterConfig, OSPF6, \
                AF_INET6, OSPF, set_rr, SHARE, CLIENT_PROVIDER, ebgp_session, bgp_peering, AccessList, \
                AF_INET, bgp_fullmesh
from ipv4 import get_IPv4, get_external_IPv4
from topology import OVH, PEERS, IGP_COSTS, RR

class ProjectTopo(IPTopo):
    """
    This topology is a small part of the OVH Network, just focusing on 
    Singapour, Sidney and their connections. This topology is hence based
    on the public available information about this website:
    http://weathermap.ovh.net/#apac
    """
    
    def build(self, *args, **kwargs):
        """
        TODO: explain topology
        """

        family = AF_INET6()
        lan_OVH_AS = "TODO"
        lan_EQUINIX_AS = "TODO"
        lan_VODAFONE_AS = "TODO"
        lan_NTT_AS = "TODO"
        lan_TELSTRA_AS = "TODO"
        lan_TATA_AS = "TODO"
        lan_LEVEL3_AS = "TODO"
        lan_SOFTBANK_AS = "TODO"
        
        ############
        # Peers AS #
        ############
        i = 2; # 1 == OVH
        for peer_name, peer in PEERS.items():
            #print("Router created : AS = {} | ip = {}".format(peer_name, get_external_IPv4(peer_name, 1)))
            print("External router created : name = {} | ip = {}".format(peer_name, get_external_IPv4(peer_name, 1)))
            peer['object'] = self.addRouter(peer_name, lo_addresses=[get_external_IPv4(peer_name, 1)])
            peer['object'].addDaemon(OSPF)
            peer['object'].addDaemon(OSPF6)
            peer['object'].addDaemon(BGP, address_families=(
                AF_INET(redistribute=('connected',)),
                AF_INET6(redistribute=('connected',))))
            # Add peers routers to their respective ASes
            self.addAS(i, [peer['object']])
            i += 1

        ##########
        # OVH AS #
        ##########
        OVH_AS = []
        for cluster_name, cluster in OVH.items():
            for router_name, router in cluster.items():
                router_nbr = int(router_name[-1])
                print("Router created : name = {} | cluster = {} | ip = {}".format(router_name, cluster_name, get_IPv4(cluster_name, router_nbr, 1)))
                router['object'] = self.addRouter(router_name, lo_addresses=[get_IPv4(cluster_name, router_nbr, 1)])
                router['object'].addDaemon(OSPF)
                router['object'].addDaemon(OSPF6)
                router['object'].addDaemon(BGP, address_families=(
                    AF_INET(redistribute=('connected',)),
                    AF_INET6(redistribute=('connected',))))
                
                if not router['meds'] is None:
                    for p in router['meds']:
                        al = AccessList(name='all', entries=('any',))
                        peer_name = list(p.keys())[0]
                        peer_router = PEERS[peer_name]['object']
                        router['object'].get_config(BGP).set_med(p[peer_name], to_peer=peer_router, matching=(al, ))
                OVH_AS.append(router['object'])

        # Add all routers to AS #1 (OVH)
        print("AS OVH = {}".format(tuple(OVH_AS)))
        self.addAS(1, tuple(OVH_AS))

        ##################
        # Physical links #
        ##################
        
        already_created = set()
        for cluster_name, cluster in OVH.items():
            for router_name, router_dict in cluster.items():
                router = router_dict['object']
                router_nbr = int(router_name[-1])
                
                for interface_nbr, peer_name in router_dict['interfaces'].items():
                    peer_cluster_name = peer_name.split('_')[0]
                    
                    if peer_cluster_name in OVH:
                        peer_router = OVH[peer_cluster_name][peer_name]['object']
                        peer_router_nbr = int(peer_name[-1])
                        peer_interface = list(OVH[peer_cluster_name][peer_name]['interfaces'].keys())[list(OVH[peer_cluster_name][peer_name]['interfaces'].values()).index(router_name)]
                        router_ip = get_IPv4(cluster_name, router_nbr, interface_nbr)
                        peer_ip = get_IPv4(peer_cluster_name, peer_router_nbr, peer_interface)
                    
                        if not (router, peer_router) in already_created and not (peer_router, router) in already_created: # Don't duplicate links
                            if cluster_name == peer_cluster_name: #Links intra-cities are considered cheap and of the same cost
                                print("LINK: {} (Interface {} - {}) <-> {} (Interface {} - {})".format(router, interface_nbr, router_ip, peer_router, peer_interface, peer_ip))
                                link_kwargs = {
                                    'params1': {
                                        'ip': router_ip
                                    },
                                    'params2': {
                                        'ip': peer_ip
                                    }   
                                }
                                self.addLink(router, peer_router, **link_kwargs)
                            else: #Links inter-cities of OVH can have a higher IGP cost
                                if (cluster_name, peer_cluster_name) in IGP_COSTS:
                                    igp_cost = IGP_COSTS[(cluster_name, peer_cluster_name)]
                                else:
                                    igp_cost = IGP_COSTS[(peer_cluster_name, cluster_name)]
                                    
                                print("LINK: {} (Interface {} - {}) <-> {} (Interface {} - {})".format(router, interface_nbr, router_ip, peer_router, peer_interface, peer_ip))
                                
                                link_kwargs = {
                                    'params1': {
                                        'ip': router_ip
                                    },
                                    'params2': {
                                        'ip': peer_ip
                                    },
                                    'igp_metric': igp_cost
                                }
                                self.addLink(router, peer_router, **link_kwargs)
                    else: #Connexinon externe
                        peer_router = PEERS[peer_cluster_name]['object']
                        peer_interface = list(PEERS[peer_cluster_name]['interfaces'].keys())[list(PEERS[peer_cluster_name]['interfaces'].values()).index(router_name)]
                        router_ip = get_IPv4(cluster_name, router_nbr, interface_nbr)
                        peer_ip = get_external_IPv4(peer_cluster_name, peer_interface)
                        
                        if not (router, peer_router) in already_created and not (peer_router, router) in already_created: # Don't duplicate links
                            print("LINK: {} (Interface {} - {}) <-> {} (Interface {} - {})".format(router, interface_nbr, router_ip, peer_router, peer_interface, peer_ip))
                            
                            link_kwargs = {}
                            link_kwargs = {
                                'param1s': {
                                    'ip': router_ip
                                },
                                'param2s': {
                                    'ip': peer_ip
                                }   
                            }
                            self.addLink(router, peer_router, **link_kwargs)
                            ebgp_session(self, peer_router, router, CLIENT_PROVIDER)
                    already_created.add((router, peer_router))

        sin_r1 = OVH['sin']['sin_r1']['object']
        sin_r2 = OVH['sin']['sin_r2']['object']
        sin_r3 = OVH['sin']['sin_r3']['object']
        sin_r4 = OVH['sin']['sin_r4']['object']
        syd_r1 = OVH['syd']['syd_r1']['object']
        syd_r2 = OVH['syd']['syd_r2']['object']
        syd_r3 = OVH['syd']['syd_r3']['object']
        syd_r4 = OVH['syd']['syd_r4']['object']
        mrs_r1 = OVH['mrs']['mrs_r1']['object']
        sjo_r1 = OVH['sjo']['sjo_r1']['object']
        lax_r1 = OVH['lax']['lax_r1']['object']
        equinix = PEERS['equinix']['object']
        vodafone = PEERS['vodafone']['object']
        ntt = PEERS['ntt']['object']
        telstra = PEERS['telstra']['object']
        franceIX = PEERS['france-IX']['object']
        level3 = PEERS['level3']['object']
        softbank = PEERS['softbank']['object']
        
         # To test OSPF
        test_ospf = True
        test_BGP = True

        if test_ospf:
            # Add a host for each router in OVH network
            h1 = self.addHost("h1")
            h2 = self.addHost("h2")
            h3 = self.addHost("h3")
            h4 = self.addHost("h4")
            h5 = self.addHost("h5")
            h6 = self.addHost("h6")
            h7 = self.addHost("h7")
            h8 = self.addHost("h8")
            h9 = self.addHost("h9")
            hA = self.addHost("hA")
            hB = self.addHost("hB")

            # Add link between each host and router
            self.addLinks((sin_r1, h1), (sin_r2, h2), (sin_r3, h3), (sin_r4, h4),
                            (syd_r1, h5), (syd_r2, h6), (syd_r3, h7), (syd_r4, h8),
                            (sjo_r1, h9), (lax_r1, hA), (mrs_r1, hB))
        elif test_BGP:
            h_equinix = self.addHost("h_equ")
            h_vodafone = self.addHost("h_vod")
            h_ntt = self.addHost("h_ntt")
            h_telstra = self.addHost("h_tel")
            h_level3 = self.addHost("h_le3")
            h_softbank = self.addHost("h_sob")
            h_franceIX = self.addHost("h_fra")

            self.addLinks((equinix, h_equinix), (vodafone, h_vodafone), (ntt, h_ntt), 
                            (telstra, h_telstra), (level3, h_level3), 
                            (softbank, h_softbank), (franceIX, h_franceIX))
        
        
        ################
        # BGP sessions #
        ################
        
        # Set RRs
        fullmesh = []
        for rr_name, rr in RR.items():
            rr_router = OVH[rr_name.split('_')[0]][rr_name]['object']
            rr_peers_routers = list(map(lambda x: OVH[x.split('_')[0]][x]['object'], rr['peers']))
            
            print("RR: router = {} || peers = {}".format(rr_router, rr_peers_routers))
            set_rr(self, rr=rr_router, peers=rr_peers_routers)
            
            fullmesh.append(rr_router)

        # Set the "full mesh" between the RRs
        bgp_fullmesh(self, tuple(fullmesh))
        
        
        # Building topology
        super().build(*args, **kwargs)
