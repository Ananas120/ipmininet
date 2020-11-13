Emulating real network link
===========================

You can emulate a real link capacity by emulating delay, losses or
throttling bandwidth with tc.

You can use the following parameters either as link parameter or interface one
to configure bandwidth shaping, delay, jitter, losses,...

- bw: bandwidth in Mbps (e.g. 10) with HTB by default
- use_hfsc: use HFSC scheduling instead of HTB for shaping
- use_tbf: use TBF scheduling instead of HTB for shaping
- latency_ms: TBF latency parameter
- enable_ecn: enable ECN by adding a RED qdisc after shaping (False)
- enable_red: enable RED after shaping (False)
- speedup: experimental switch-side bw option (switches-only)
- delay: transmit delay (e.g. ‘1ms’) with netem
- jitter: jitter (e.g. ‘1ms’) with netem
- loss: loss (e.g. ‘1%’ ) with netem
- max_queue_size: queue limit parameter for the netem qdisc
- gro: enable GRO (False)
- txo: enable transmit checksum offload (True)
- rxo: enable receive checksum offload (True)

You can pass parameters to links and interfaces when calling ``addLink()``:

.. testcode:: tc

    from ipmininet.iptopo import IPTopo

    class MyTopology(IPTopo):

        def build(self, *args, **kwargs):
            h1 = self.addHost("h1")
            r1 = self.addRouter("r1")
            r2 = self.addRouter("r2")
            h2 = self.addHost("h2")

            # Set maximum bandwidth on the link to 100 Mbps
            self.addLink(h1, r1, bw=100)

            # Sets delay in both directions to 15 ms
            self.addLink(r1, r2, delay="15ms")

            # Set delay only for packets going from r2 to h2
            self.addLink(r2, h2, params1={"delay": "2ms"})

            super().build(*args, **kwargs)


More accurate performance evaluations
-------------------------------------

If you wish to do performance evaluation, you should be aware of a few
pitfalls that are reported at the following links:

- https://progmp.net/mininetPitfalls.html
- Section 3.5.2 of https://inl.info.ucl.ac.be/system/files/phdthesis-lebrun.pdf

In practise, we advise you against putting netem delay requirements on the
machines originating the traffic but you still need that delays of at least 2ms
to enable scheduler preemption on the path.

Also, for accurate throttling of the bandwidth, you should not use bandwidth
constraints on the same interface as delay requirements. Otherwise, the tc-htb
computations to shape the bandwidth will be messed by the potentially large
netem queue placed afterwards.

To accurately model delay and bandwidth, we advise you to create one switch
between each pair of nodes that you want to link and place delay, loss and
any other tc-netem requirements on switch interfaces while leaving the
bandwidth shaping on the original nodes.

You can automate that by extending the addLink method of your IPTopo subclass
in the following way:

.. testcode:: tc performance

    from ipmininet.iptopo import IPTopo
    from ipmininet.ipnet import IPNet

    class MyTopology(IPTopo):
        def __init__(self, *args, **kwargs):
            self.switch_count = 0
            super().__init__(*args, **kwargs)

        def build(self, *args, **kwargs):
            h1 = self.addHost("h1")
            r1 = self.addRouter("r1")
            r2 = self.addRouter("r2")
            h2 = self.addHost("h2")

            self.addLink(h1, r1, bw=100, delay="15ms")
            self.addLink(r1, r2, bw=10, delay="5ms")
            self.addLink(r2, h2, bw=1000, params1={"delay": "7ms"})

            super().build(*args, **kwargs)

        # We need at least 2ms of delay for accurate emulation
        def addLink(self, node1, node2, delay="2ms", bw=None,
                    max_queue_size=None, **opts):
            src_delay = None
            dst_delay = None
            opts1 = dict(opts)
            if "params2" in opts1:
                opts1.pop("params2")
            try:
                src_delay = opts.get("params1", {}).pop("delay")
            except KeyError:
                pass
            opts2 = dict(opts)
            if "params1" in opts2:
                opts2.pop("params1")
            try:
                dst_delay = opts.get("params2", {}).pop("delay")
            except KeyError:
                pass

            src_delay = src_delay if src_delay else delay
            dst_delay = dst_delay if dst_delay else delay

            # node1 -> switch
            default_params1 = {"bw": bw}
            default_params1.update(opts.get("params1", {}))
            opts1["params1"] = default_params1

            # node2 -> switch
            default_params2 = {"bw": bw}
            default_params2.update(opts.get("params2", {}))
            opts2["params2"] = default_params2

            # switch -> node1
            opts1["params2"] = {"delay": dst_delay,
                                "max_queue_size": max_queue_size}
            # switch -> node2
            opts2["params1"] = {"delay": src_delay,
                                "max_queue_size": max_queue_size}

            # Netem queues will mess with shaping
            # Therefore, we put them on an intermediary switch
            self.switch_count += 1
            s = "s%d" % self.switch_count
            self.addSwitch(s)
            return super().addLink(node1, s, **opts1), \
                   super().addLink(s, node2, **opts2)

Feel free to add other arguments but make sure that tc-netem arguments are
used at the same place as delay and tc-htb ones at the same place as bandwidth.

Last important note: you should be careful when emulating delays in a VM with
multiple CPUs. On virtualbox, we observed that netem delays can vary by
several hundreds of milliseconds. Setting the number of CPUs to 1 fixed the
issue.

.. doctest related functions

.. testsetup:: *

    from ipmininet.clean import cleanup
    cleanup(level='warning')

.. testcode:: *
    :hide:

    try:
        MyTopology
    except NameError:
        MyTopology = None

    if MyTopology is not None:
        from ipmininet.ipnet import IPNet
        net = IPNet(topo=MyTopology())
        net.start()

.. testcleanup:: *

    try:
        net
    except NameError:
        net = None

    if net is not None:
        net.stop()
