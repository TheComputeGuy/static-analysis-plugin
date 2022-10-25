from collections import defaultdict
from typing import *
from cfg_constants import *
import idc
import idaapi


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
        self.ddList = set()
        self.xrefsFromNode = []
        self.xrefsToNode = []
        self.symbolDefHistory = defaultdict(str)
        self.shadowStack = []

    def __str__(self):
        # output_def_list = ','.join(entry for entry in self.defList)
        # output_use_list = ','.join(entry for entry in self.useList)
        # output_str = '\t' + self.nodenum + ' [label=\"' + str(self.label) + '; D:' + output_def_list + ' U:' + output_use_list + '\"]\n'
        output_dd_list = ','.join(entry for entry in self.ddList)
        output_str = '\t' + self.nodenum + ' [label=\"' + str(self.label) + '; DD:' + output_dd_list + '\"]\n'
        return output_str


class CfgEdge():
    def __init__(self, head, tail):
        self.head = head
        self.tail = tail

    def __eq__(self, other):
        if isinstance(other, CfgEdge):
            return self.head==other.head and self.tail==other.tail

    def __str__(self):
        output_str = '\t' + str(self.head) + ' -> ' + str(self.tail) + '\n'
        return output_str


class Digraph():
    def __init__(self, nodes: List[CfgNode], edges: List[CfgEdge]):
        self.nodes = nodes
        self.edges = edges
        self.ddEdges = []

        self.nodeLabelDict = {}
        for node in self.nodes:
            self.nodeLabelDict[node.label] = node

        self.nodenumDict = {}
        for node in self.nodes:
            self.nodenumDict[node.nodenum] = node

        for edge in self.edges:
            headNode: CfgNode = self.nodenumDict[edge.head]
            tailNode: CfgNode = self.nodenumDict[edge.tail]
            headNode.xrefsFromNode.append(tailNode.nodenum)
            tailNode.xrefsToNode.append(headNode.nodenum)
            self.nodenumDict[edge.head] = headNode
            self.nodenumDict[edge.tail] = tailNode

    def _DDListUtil(self, node: CfgNode, visited: List[str]):
        visited.append(node.nodenum)
        mnemonic = idc.print_insn_mnem(node.address)

        for use in node.useList:
            lastDef = START_NODE_LABEL

            if use in SMALL_REGISTERS:
                checkVars = [use]
                if use == AL or use == AH:
                    checkVars = checkVars + A_EQV
                if use == BL or use == BH:
                    checkVars = checkVars + B_EQV
                if use == CL or use == CH:
                    checkVars = checkVars + C_EQV
                if use == DL or use == DH:
                    checkVars = checkVars + D_EQV
                if use == AX:
                    checkVars = A_EQV
                if use == BX:
                    checkVars = B_EQV
                if use == CX:
                    checkVars = C_EQV
                if use == DX:
                    checkVars = D_EQV

                varsDefined = [(varToCheck in list(node.symbolDefHistory.keys())) for varToCheck in checkVars]

                if(any(varsDefined)):
                    eqvDefs = []
                    for indx, varToCheck in enumerate(checkVars):
                        if varsDefined[indx]:
                            eqvDefs.append(node.symbolDefHistory[varToCheck])
                    eqvDefs = sorted(eqvDefs)
                    lastDef = eqvDefs[-1]

            if ESP in use:
                if ESP_ADDR in use:
                    lastDef = node.symbolDefHistory[use]
                else:
                    if PUSH in mnemonic or POP in mnemonic:
                        try:
                            lastDef = node.shadowStack[-1]
                        except IndexError:
                            lastDef = node.symbolDefHistory[use]
                    if CALL in mnemonic:
                        args = idaapi.get_arg_addrs(node.address)
                        if args:
                            for farg in args:
                                lastDef = hex(farg)[2:].zfill(8)
                                node.ddList.add(lastDef)
                                edge = CfgEdge(node.nodenum, self.nodeLabelDict[lastDef].nodenum)
                                if edge not in self.ddEdges:
                                    self.ddEdges.append(edge)
                                continue

            if use in list(node.symbolDefHistory.keys()):
                lastDef = node.symbolDefHistory[use]
            # TODO: data def for looping
            if lastDef:
                node.ddList.add(lastDef)
                edge = CfgEdge(node.nodenum, self.nodeLabelDict[lastDef].nodenum)
                if edge not in self.ddEdges:
                    self.ddEdges.append(edge)

        for symbol in node.defList:
            if ESP in symbol:
                if ESP_ADDR in symbol:
                    if PUSH in mnemonic:
                        node.symbolDefHistory[symbol] = node.label
                        continue
                else:
                    if PUSH in mnemonic:
                        node.shadowStack.append(node.label)
                    if CALL in mnemonic:
                        # stack is restored after the call so no changes here
                        continue
                if POP in mnemonic:
                    try:
                        node.shadowStack.pop()
                    except IndexError:
                        pass
            node.symbolDefHistory[symbol] = node.label

        for i in node.xrefsFromNode:
            if i not in visited:
                self._DDListUtil(self.nodenumDict[i], visited)

    def generateDDList(self):
        visited = []
        symbolDefHistory = defaultdict(str)
        shadowStack = []
        for node in self.nodes[1:]:
            node.symbolDefHistory = symbolDefHistory
            node.shadowStack = shadowStack
            if node not in visited:
                self._DDListUtil(node, visited)
            symbolDefHistory = node.symbolDefHistory
            shadowStack = node.shadowStack

    def __str__(self):
        prologue = 'digraph {\n'
        nodes_human_representation = ''
        edges_human_representation = ''

        for node in list(self.nodenumDict.values()):
            nodes_human_representation = nodes_human_representation + str(node)

        # for edge in self.edges:
        #     edges_human_representation = edges_human_representation + str(edge)

        for edge in self.ddEdges:
            edges_human_representation = edges_human_representation + str(edge)

        epilogue = '\n}'

        output_str = prologue + nodes_human_representation + '\n' + edges_human_representation + epilogue
        return output_str