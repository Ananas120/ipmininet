# LINGI2145 project. 

This is a fork from [ipmininet](https://github.com/cnp3/ipmininet) for the LINGI2145 course project. 

**Authors** :
- Langlois Quentin - 19-28-1700
- Dardenne Florent - 02-60-1700
- Iavarone Simon - 29-91-1700

**Professor** : Bonaventure Olivier

## Structure

Here is a description of the structure of the project : 
- `ipmininet/`  : ipmininet library code modified for the needs of our project. 
- `ovh_topologies/` : `json` files representing some version of our topologie. 
- `project_tests/`  : some basic topologies in order to test different aspects such as anycast and BGP communities. 
- `report/`         : files for the report (images, and .tex file). 
- `ipaddr_utils.py`     : some utilities functions to manipulate IP addresses. 
- `json_topo.py`    : the main class of our project. 
- `plot_utils.py`   : utility function to plot a json-formatted topology. 
- `topo_plot.ipynb` : jupyter notebook to plot the topology. 

## Configuration and run

In order to run our topology, you just have to run `sudo python3 json_topo.py` in the vagrant terminal. 

In the `json_topo.py` file, you can change, at the end, the arguments of the `JSONTopo` constructor : 
- `filename`    : a `.json` formatted file (on of the files in `ovh_topologies` for instance)
- `debug`       : the verbosity of the topology generation. 
- `add_hosts`   : the number of fictitious hosts to add and where (useful to test the `ping6all` command). 
- `infer_ip`    : whether to generate loopback / link addresses. 

Note : you can change the `filename` argument by another topology file : 
- `topo_simple.json`    : simple topology without communities / security, just anycast. 
- `topo_communities.json`   : topology with anycast an communities
- `topo_security.json`  : topology with anycast and security
- `topo_complete.json`  : topology with anycast, communities and security

We decided to create multiple topologies in order to test that our modification in the code for one specific topology does not affect other topologies. 

## Description of the JSON format. 

Here is a description of entries you can add in the JSON formatted file. 

**Note** You can also find a documented example in the section 4.1 of our report. 

- `subnets` : the subnets used in the network as dict `{subnet_name : subnet_config}` where `subnet_config` can contain :
    - `ipv4`    : the ipv4 address of the subnet 
    - `ipv6`    : the ipv6 address of the subnet
    - `nodes`   : the routers names which are in the subnet
- `AS`  : ASes in the topology represented as `as_name : as_config` where config can contain : 
    - `ASN`     : the ASN for this AS (if not specified, generated incrementally)
    - `routers`     : a dict `{router_name : router_config}` with possible configs : 
        - `daemons`         : a list of daemons or dict `{damoemon_name : daemon_config}`
        - `lo_addresses`    : dict `{ipv4 :, ipv6 :}`
    - `hosts`       : dict of `{host_name : host_config}`
    - `rconfig`     : default configuration for routers
    - `linked`      : create a full-mesh of physical links inside the AS. 
    - `bgp_fullmesh`    : create a fullmesh of iBGP connections inside the AS. 
- `links`   : dict of links `{node_name : list of neighbors}`
    - the neighborhood list can either contain simple node name or a list with 2 elements `[neightbor name, link_config]` where config can contains, for example, `igp_metric`. 