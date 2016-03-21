#!/usr/bin/env python

from gh.connect import Connect
import gh
from gephistreamer import graph
from gephistreamer import streamer

def display_graph(stream, nodes, edges):

    if nodes != None:
        print "*** Graphing Nodes"
        for n in nodes:
            node_temp = graph.Node(n._id)

            properties = n.map()
            for key in properties:
                node_temp.property[key] = properties[key]

            node_temp.property["colour"] = node_temp.property["color"]
            node_temp.property["label"] = node_temp.property["name"]
            stream.add_node(node_temp)

    if edges != None:
        print "*** Graphing Edges"
        for e in edges:
            src = e._outV
            dst = e._inV
            edge_temp = graph.Edge(src, dst, directed=True)

            properties = e.map()
            for key in properties:
                edge_temp.property[key] = properties[key]
            
            stream.add_edge(edge_temp)
    stream.commit()

if __name__ == "__main__":
    g = Connect()
    #t = GephiStreamerManager()
    stream = streamer.Streamer(streamer.GephiREST())

    print "Getting nodes..."
    nodes = g.V
    print len(nodes)
    print "Getting edges..."
    edges = g.E
    print len(edges)

    display_graph(stream, g.V, g.E)

