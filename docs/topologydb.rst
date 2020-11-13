Dumping the network state
=========================

You might need to access the state of the network (e.g., the nodes, the links
or the assigned ip addresses) from a program outside of the python script
launching the network. IPMininet allows you to dump the state of network to a
JSON file through the :class:`~ipmininet.topologydb.TopologyDB` class.

The following code stores the network state to "/tmp/topologydb.json" and
load it again afterwards. Note that you can read this file from any
other program that can parse JSON files.

.. testcode:: topologydb

    from ipmininet.iptopo import IPTopo
    from ipmininet.ipnet import IPNet
    from ipmininet.topologydb import TopologyDB

    class MyTopology(IPTopo):
        pass  # Any topology

    net = IPNet(topo=MyTopology())
    try:
        # This saves the state of the network to "/tmp/topologydb.json"
        db = TopologyDB(net=net)
        db_path =  "/tmp/topologydb.json"
        db.save(db_path)

        # This can be recovered from a new TopologyDB object or by loading
        # the json file in any other program
        TopologyDB(db=db_path)

        # The backup of the network can be done before or after the start of
        # the daemons. Here it is done before.
        net.start()
    except:
        net.stop()

The produced JSON file has the following format:

.. code-block:: json

    {
        "<node-name>": {
            "type": "<node-type>",
            "interfaces": ["<itf1-name>"],
            "<itf1-name>": {
                "ip": "<itf1-ip1-with-prefix-len>",
                "ips": ["<itf1-ip1-with-prefix-len>",
                        "<itf1-ip2-with-prefix-len>"],
                "bw": 10
            },
            "<neighbor1-name>": {
                "name": "<itf1-name>",
                "ip": "<itf1-ip1-with-prefix-len>",
                "ips": ["<itf1-ip1-with-prefix-len>",
                        "<itf1-ip2-with-prefix-len>"],
                "bw": 10
            }
        }
    }

Note that the ``<node-type>`` can be any of ``switch``, ``router`` or ``host``.


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
