import argparse

import ipmininet
from ipmininet.ipnet import IPNet
from ipmininet.cli import IPCLI
from topo_builder import ProjectTopo

from mininet.log import lg, LEVELS

TOPOS = {'first_topo': ProjectTopo}

NET_ARGS = {'router_adv_network':  {'use_v4': False,
                                    'use_v6': True,
                                    'allocate_IPs': False},
            'bgp_full_config':     {'use_v4': False,
                                    'use_v6': True},
            'bgp_local_pref':      {'use_v4': False,
                                    'use_v6': True},
            'bgp_med':             {'use_v4': False,
                                    'use_v6': True},
            'bgp_rr':              {'use_v4': False,
                                    'use_v6': True}}


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--topo', choices=TOPOS.keys(),
                        default='first_topo',
                        help='The topology that you want to start.')
    parser.add_argument('--log', choices=LEVELS.keys(), default='info',
                        help='The level of details in the logs.')
    parser.add_argument('--args', help='Additional arguments to give'
                        'to the topology constructor (key=val, key=val, ...)',
                        default='')
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    lg.setLogLevel(args.log)
    if args.log == 'debug':
        ipmininet.DEBUG_FLAG = True
    kwargs = {}
    for arg in args.args.strip(' \r\t\n').split(','):
        arg = arg.strip(' \r\t\n')
        if not arg:
            continue
        try:
            k, v = arg.split('=')
            kwargs[k] = v
        except ValueError:
            lg.error('Ignoring args:', arg)
    net = IPNet(topo=TOPOS[args.topo](**kwargs), **NET_ARGS.get(args.topo, {}))
    net.start()
    IPCLI(net)
    net.stop()