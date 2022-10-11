from typing import *

class CfgNode():
    def __init__(self, nodenum, address, label=None, defList = [], useList = []):
        self.nodenum = 'n' + str(nodenum)
        self.address = address
        if label:
            self.label = label
        else:
            self.label = address
        self.defList = defList
        self.useList = useList

    def __str__(self):
        output_def_list = ','.join(entry for entry in self.defList)
        output_use_list = ','.join(entry for entry in self.useList)
        output_str = '\t' + self.nodenum + ' [label=\"' + str(self.label) + '; D:' + output_def_list + ' U:' + output_use_list + '\"]\n'
        return output_str


class CfgEdge():
    def __init__(self, head, tail):
        self.head = head
        self.tail = tail

    def __str__(self):
        output_str = '\t' + str(self.head) + ' -> ' + str(self.tail) + '\n'
        return output_str


class Digraph():
    def __init__(self, nodes: List[CfgNode], edges: List[CfgEdge]):
        self.nodes = nodes
        self.edges = edges

    def __str__(self):
        prologue = 'digraph {\n'
        nodes_human_representation = ''
        edges_human_representation = ''

        for node in self.nodes:
            nodes_human_representation = nodes_human_representation + str(node)

        for edge in self.edges:
            edges_human_representation = edges_human_representation + str(edge)

        epilogue = '\n}'

        output_str = prologue + nodes_human_representation + '\n' + edges_human_representation + epilogue
        return output_str