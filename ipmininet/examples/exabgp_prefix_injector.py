import itertools
import random
from ipaddress import ip_network, ip_address, ip_interface, IPv4Interface, IPv6Interface, IPv4Network, IPv6Network
from typing import Sequence, List, Optional, Dict, Union

from ipmininet.iptopo import IPTopo
from ipmininet.router.config import ebgp_session, RouterConfig, BGP, ExaBGPDaemon, BGPRoute, BGPAttribute, \
    ExaList
from ipmininet.router.config.bgp import AF_INET, AF_INET6

__MAX_UINT128_ = 340282366920938463463374607431768211455
__MAX_UINT32_ = 4294967295
__MAX_UINT16_ = 65535

_1_0_0_0 = 16777216  # int repr of IPv4 address 1.0.0.0
_2001 = 42540488161975842760550356425300246528  # int repr of IPv6 address 2001::


def rnd_list(max_len: int, strict=False, bound_lo: int = 1, bound_hi: int = __MAX_UINT16_) -> List[int]:
    """
    Generates a list of random integers in the limits [bound_lo; bound_hi[
    of at most max_len elements

    :param max_len: the maximum number of random integer to generate
    :param strict: if set to True, the generated list will contains exactly 
                   max_len random integers len(generated_list) = max_sub_rnd_list.
                   If set to False, 1 <= len(generated_list) <= max_sub_rnd_list
    :param bound_lo: randomly generated integers >= bound_lo
    :param bound_hi: randomly generated integers < bound_hi
    :return: a list of random integers of at most max_len elements. Each
             element of this list are generated in the bounds [bound_lo; bound_hi[.
    """

    def random_gen(low: int, high: int):
        """Generator of integers in the bounds [low; high["""
        while True:
            yield random.randrange(low, high)

    rnd_set = set()
    generator = random_gen(bound_lo, bound_hi)
    lst_len = random.randint(1, max_len) if not strict else max_len

    for x in itertools.takewhile(lambda _: len(rnd_set) <= lst_len, generator):
        rnd_set.add(x)

    return list(rnd_set)


def build_bgp_route(ip_networks: Union[Sequence['IPv4Network'], Sequence['IPv6Network']], my_as: int):
    """
    Generates BGP routes with custom attributes attached to IP prefixes given
    at argument.

    :param ip_networks: sequence of valid IP prefixes that will be used to generate
                        BGP routes.
    :param my_as: the ASN that will be prepended to the randomly generated AS-PATH
    :return: a list of BGP route, actually one per prefixes of ip_networks,
             with random BGP attributes
    """

    my_routes = list()

    for network in ip_networks:
        next_hop = BGPAttribute("next-hop", "self")
        as_path = BGPAttribute("as-path", ExaList([my_as] + rnd_list(random.randint(1, 25))))
        communities = BGPAttribute("community",
                                   ExaList(["%d:%d" % (j, k) for j, k in zip(rnd_list(24, True), rnd_list(24, True))]))
        med = BGPAttribute("med", random.randint(1, __MAX_UINT32_))
        origin = BGPAttribute("origin", random.choice(["igp", "egp", "incomplete"]))

        my_routes.append(BGPRoute(network, [next_hop, origin, med, as_path, communities]))

    return my_routes


def gen_ip_prefix(family: str):
    """Generates a random IP prefix according to the family given at argument
    """
    assert family in {'ipv4', 'ipv6'}, 'Family "%s" is not a valid IP family' % family

    _CONF_FAMILY = {
        'ipv4': {
            'pfx_lo': 8,
            'pfx_hi': 32,
            'start_ip': _1_0_0_0,  # 1.0.0.0
            'end_ip': __MAX_UINT32_  # 255.255.255.255
        },
        'ipv6': {
            'pfx_lo': 16,
            'pfx_hi': 128,
            'start_ip': _2001,  # 2001::
            'end_ip': __MAX_UINT128_  # ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
        }
    }

    def random_prefix(afi):
        ip_conf = _CONF_FAMILY[afi]
        mask_len = random.randint(ip_conf['pfx_lo'], ip_conf['pfx_hi'])
        int_addr = random.randint(ip_conf['start_ip'], ip_conf['end_ip'])

        return ip_network("{addr}/{mask}"
                          .format(addr=ip_address(int_addr), mask=mask_len),
                          strict=False)

    while True:
        if family == 'ipv4':
            yield random_prefix(family)
        elif family == 'ipv6':
            yield random_prefix(family)


class ExaBGPTopoInjectPrefixes(IPTopo):
    """
    This simple topology made up of 2 routers, as1 and as2 from both different
    ASN, shows an example on how to use ExaBGP to inject both IPv4 and IPv6
    routes to its remote peer. as1 node runs ExaBGP and as2 runs FRRouting BGPD.
    """

    def __init__(self, routes: Optional[Dict[str, Sequence['BGPRoute']]] = None,
                 addr: Optional[Dict[str, Dict[str, Union[str, 'IPv4Interface', 'IPv6Interface']]]] = None,
                 *args, **kwargs):
        """
        Initialize the topology example.

        :param routes: Routes that ExaBGP node (as1) will inject to as2. If the
                       parameter is None, the constructor will assign random
                       BGP routes. That is, 5 IPv6 unicast routes and
                       5 IPv4 unicast routes. BGP Attributes will be set to random
                       too (as-path, community, med, origin).
        :param addr: IP addresses to be set on the interfaces of both as1 and as2.
                     Default are :

                     * as1: ```10.1.0.1/24``` and ```fd00:12::1/64```
                     * as2: ```10.1.0.2/24``` and ```fd00:12::2/64```

                     It is possible to change either IP addresses of as1 or as2.
                     Also, it is possible to only change the IPv4 or IPv6 of the
                     node. In this case, the untouched IP address will be set to
                     the default one.
        """
        self.routes = {'ipv4': list(), 'ipv6': list()}
        self.addr = {'as1': {'ipv4': ip_interface("10.1.0.1/24"), 'ipv6': ip_interface("fd00:12::1/64")},
                     'as2': {'ipv4': ip_interface("10.1.0.2/24"), 'ipv6': ip_interface("fd00:12::2/64")}}

        if routes is None:
            self.routes = dict()
            for afi in ('ipv4', 'ipv6'):
                prefixes = set()
                for x in itertools.takewhile(lambda _: len(prefixes) <= 5, gen_ip_prefix(afi)):
                    prefixes.add(x)

                self.routes[afi] = build_bgp_route(list(prefixes), self.exabgp_asn)
        else:
            for key in self.routes.keys():
                self.routes[key].extend(routes[key])

        if addr is not None:
            for node in addr.keys():
                assert node in {'as1', 'as2'}, 'Unrecognized node: "%s". Expected: "as1" or "as2"' % node
                for afi in addr[node].keys():
                    assert afi in {'ipv4', 'ipv6'}, 'Unrecognized AFI "%s" for "%s" node. ' \
                                                    'Expected: "ipv4" or "ipv6"' % (afi, node)

                    if isinstance(addr[node][afi], str):
                        self.addr[node][afi] = ip_interface(addr[node][afi])
                    else:
                        assert isinstance(addr[node][afi], IPv4Interface) or \
                               isinstance(addr[node][afi], IPv6Interface), \
                               "Bad type '{type}' for {afi} AFI. Expected: IPv4Interface or IPv6Interface or str." \
                               .format(type=type(addr[node][afi]), afi=afi)

                        self.addr[node][afi] = addr[node][afi]

        super().__init__(*args, **kwargs)

    @property
    def exabgp_asn(self):
        return 1

    def build(self, *args, **kwargs):
        """
          +---+---+---+     +---+---+---+
          |           |     |           |
          |    as1    |     |    as2    |
          |   ExaBGP  +-----+  FRR BGP  |
          |           |     |           |
          +---+---+---+     +---+---+---+
        """

        af4 = AF_INET(routes=self.routes['ipv4'])
        af6 = AF_INET6(routes=self.routes['ipv6'])

        # Add all routers
        as1r1 = self.addRouter('as1', config=RouterConfig, use_v4=True, use_v6=True)
        as1r1.addDaemon(ExaBGPDaemon, address_families=(af4, af6))

        as2r1 = self.bgp('as2')

        # Add links
        las12 = self.addLink(as1r1, as2r1)
        las12[as1r1].addParams(ip=(str(self.addr['as1']['ipv4']), str(self.addr['as1']['ipv6'])))
        las12[as2r1].addParams(ip=(str(self.addr['as2']['ipv4']), str(self.addr['as2']['ipv6'])))

        # Set AS-ownerships
        self.addAS(self.exabgp_asn, (as1r1,))
        self.addAS(2, (as2r1,))
        # Add eBGP peering
        ebgp_session(self, as1r1, as2r1)

        # Add test hosts
        for r in self.routers():
            self.addLink(r, self.addHost('h%s' % r))
        super().build(*args, **kwargs)

    def bgp(self, name):
        r = self.addRouter(name, use_v4=True, use_v6=True)
        r.addDaemon(BGP, address_families=(
            AF_INET(redistribute=('connected',)),
            AF_INET6(redistribute=('connected',))))
        return r
