"""Base classes to configure an OSPF daemon"""
from ipaddress import ip_interface

from .zebra import QuaggaDaemon, Zebra
from .utils import ConfigDict
from ipmininet.utils import otherIntf, L3Router, realIntfList
from ipmininet.link import address_comparator


class OSPF(QuaggaDaemon):
    """This class provides a simple configuration for an OSPF daemon.
    It advertizes one network per interface (the primary one), and set
    interfaces not facing another L3Router to passive"""
    NAME = 'ospfd'
    DEPENDS = (Zebra,)

    def __init__(self, *args, **kwargs):
        super(OSPF, self).__init__(*args, **kwargs)

    def build(self):
        cfg = super(OSPF, self).build()
        cfg.redistribute = self.options.redistribute
        cfg.debug = self.options.debug
        cfg.router_id = self.routerid
        interfaces = [itf
                      for itf in realIntfList(self._node)]
        cfg.interfaces = self._build_interfaces(interfaces)
        cfg.networks = self._build_networks(interfaces)
        return cfg

    def _build_networks(self, interfaces):
        """Return the list of OSPF networks to advertize from the list of
        active OSPF interfaces"""
        return [OSPFNetwork(domain=ip_interface('%s/%s' % (i.ip, i.prefixLen)),
                            area=i.igp_area) for i in interfaces]

    def _build_interfaces(self, interfaces):
        """Return the list of OSPF interface properties from the list of
        active interfaces"""
        return [ConfigDict(description=i.describe,
                           name=i.name,
                           # Is the interface between two routers?
                           active=self.is_active_interface(i),
                           priority=i.get('ospf_priority',
                                          self.options.priority),
                           dead_int=i.get('ospf_dead_int',
                                          self.options.dead_int),
                           hello_int=i.get('ospf_hello_int',
                                           self.options.hello_int),
                           cost=i.igp_metric,
                           # Is the interface forcefully disabled?
                           passive=i.get('igp_passive', False))
                for i in interfaces]

    def set_defaults(self, defaults):
        """:param dead_int: Dead interval timer
        :param hello_int: Hello interval timer
        :param cost: metric for interface
        :param priority: priority for the interface, used for DR election
        :param redistribute: set of OSPFRedistributedRoute sources"""
        defaults.dead_int = 3
        defaults.hello_int = 1
        defaults.priority = 10
        defaults.redistribute = ()
        super(OSPF, self).set_defaults(defaults)

    def is_active_interface(self, itf):
        """Return whether an interface is active or not for the OSPF daemon"""
        return L3Router.is_l3router_intf(otherIntf(itf))

    @property
    def routerid(self):
        """Return the OSPF router-id for this router. It defaults to the
        most-visible address among this router interfaces."""
        return str(sorted((ip
                           for itf in realIntfList(self._node)
                           for ip in itf.ips()),
                          cmp=address_comparator).pop().ip)


class OSPFNetwork(object):
    """A class holding an OSPF network properties"""

    def __init__(self, domain, area):
        self.domain = domain
        self.area = area


class OSPFRedistributedRoute(object):
    """A class representing a redistributed route type in OSPF"""

    def __init__(self, subtype, metric_type=1, metric=1000):
        self.subtype = subtype
        self.metric_type = metric_type
        self.metric = metric
