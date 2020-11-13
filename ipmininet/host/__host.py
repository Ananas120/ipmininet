"""This modules defines a host class,
   with a modular config system."""
from typing import Type, Union, Tuple, Dict

import mininet.node as _m

from ipmininet.router import IPNode
from ipmininet.host.config.base import HostConfig


class IPHost(IPNode):
    """A Host which manages a set of daemons"""

    def __init__(self, name,
                 config: Union[Type[HostConfig],
                               Tuple[Type[HostConfig], Dict]] = HostConfig,
                 *args, **kwargs):
        super().__init__(name, config=config, *args, **kwargs)


CPULimitedHost = _m.CPULimitedHost
CPULimitedHost.__bases__ = (IPHost,)
