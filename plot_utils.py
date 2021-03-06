import os
import json
import graphviz as gv

_graphviz_path = 'C:/Program Files (x86)/Graphviz2.38/bin'
os.environ['path'] += os.pathsep + _graphviz_path

R_SHAPE     = 'circle'
RR_SHAPE    = 'doublecircle'
HOST_SHAPE  = 'egg'

def to_graphviz(topo_config, filename = 'topo_plot.gv', ebgp_color = 'red', kwargs = {}, ** sub_kwargs):
    """
        Function to convert BGP topology (configured as a json file) to a pygraphviz Grav instance. 
        
        Arguments : 
            - topo_config   : dict or .json filename
            - filename      : filename to save the plot (.gv file)
            - kwargs        : values to the 'Graph.attr()' method
            - ** sub_kwargs : kwargs to the 'Graph.attr()' method for sub-graph (the AS)
        Return : 
            - graph : pygraphviz.Graph instance
        
        Structure of the json file (or dict) : 
        {
            links : {
                router_name : list_of_voisins
                ...
            },
            AS      : {
                routers : {
                    router_name : dict (config router)
                        - if RR : should have a 'clients' entry with the list of client-routers
                    ...
                },
                hosts : {
                    host_name : {} (unused value),
                    ...
                }
            }
        }
        
        Prerequisites : 
            - install Graphviz to default path
            - pip install pygraphviz json
    """
    # if json file, load the topology
    if isinstance(topo_config, str):
        with open(topo_config, 'r', encoding = 'utf-8') as file:
            topo_config = file.read()
        topo_config = json.loads(topo_config)
    
    g = gv.Graph('Network Topology', filename = filename)
    g.attr(compound = 'true', ** kwargs)
    
    ases = {}
    as_edges = {}
    ebgp_edges = []
    
    # Set all nodes to respective AS
    for as_name, as_config in topo_config['AS'].items():
        ases[as_name] = list(as_config['routers'].keys()) + list(as_config.get('hosts', {}).keys())
    
    # Associate all links to their AS
    # If trans-AS links, add them to the eBGP-links
    for node, voisins in topo_config['links'].items():
        as_1 = [as_name for as_name, as_r in ases.items() if node in as_r][0]
        config = {}
        if isinstance(voisins, dict):
            config = voisins
            voisins = config.pop('voisins')
        if not isinstance(voisins, (list, tuple)): voisins = [voisins]
        
        for voisin in voisins:
            voisin_config = {}
            if isinstance(voisin, list):
                voisin, voisin_configconfig = voisin
            voisin_config = {** config, ** voisin_config}
            
            as_2 = [as_name for as_name, as_r in ases.items() if voisin in as_r]
            if len(as_2) == 0:
                print("Error with {}".format(voisin))
                return None
            as_2 = as_2[0]
            
            kwargs = {'label' : [], 'weight' : '5'}
            if 'igp_metric' in voisin_config:
                kwargs['label'].append('IGP = {}'.format(voisin_config['igp_metric']))
                kwargs['weight'] = str(5 - kwargs.get('igp_metric', 1))
            if 'med' in voisin_config:
                kwargs['label'].append('MED = {}'.format(voisin_config['med']))
                kwargs['weight'] = str(5 - kwargs.get('med', 1))
            if 'subnet' in voisin_config:
                kwargs['label'].append('{}'.format(voisin_config['subnet']))
            if len(kwargs['label']) == 0: kwargs.pop('label')
            else: kwargs['label'] = '\n'.join(kwargs['label'])
            
            
            
            edge = [node, voisin, kwargs]
            if as_1 == as_2:
                as_edges.setdefault(as_1, [])
                as_edges[as_1].append(edge)
            else:
                ebgp_edges.append(edge)
    
    # For each AS, create a sub_graph, add their respective nodes (routeurs / hosts)
    # and put links intra-AS. 
    for as_name, as_config in topo_config['AS'].items():
        with g.subgraph(name = 'cluster_' + as_name) as as_graph:
            as_graph.attr(** sub_kwargs, label = as_name)
            rr_graph = gv.Graph(name = as_name + '_rr')
            r_graph = gv.Graph(name = as_name + 'routeurs')
            h_graph = gv.Graph(name = as_name + '_hosts')
            
            r_graph.attr(rank = 'same')
            h_graph.attr(rank = 'same')
            
            for r_name, r_config in as_config['routers'].items():
                config = {}
                if 'clients' in r_config:
                    rr_graph.node(r_name, shape = RR_SHAPE)
                else:
                    r_graph.node(r_name, shape = R_SHAPE)
                #config['shape'] = R_SHAPE if 'clients' not in r_config else RR_SHAPE
                #config['rank'] = 'sink' if 'clients' not in r_config else 'max'
                #as_graph.node(r_name, ** config)
                
            as_graph.subgraph(rr_graph)
            as_graph.subgraph(r_graph)
            as_graph.subgraph(h_graph)
                
            for h_name in as_config.get('hosts', {}).keys():
                h_graph.node(h_name, shape = HOST_SHAPE, rank = 'min')
            
            for start, end, config in as_edges.get(as_name, []):
                as_graph.edge(start, end, ** config)
    
    # Make links between nodes from different AS (eBGP connections)
    for start, end, config in ebgp_edges:
        config['color'] = ebgp_color
        g.edge(start, end, ** config)
    
    return g
