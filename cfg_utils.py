import idautils
from models.base_classes import *

START = "Start"

def getNodes(func) -> List[CfgNode]:
    instructions = [instr for instr in idautils.Heads(func.start_ea, func.end_ea)]
    funcNodes = []
    startNode = CfgNode(0, START)
    funcNodes.append(startNode)
    for indx, instr in enumerate(instructions):
        node = CfgNode(indx + 1, instr, hex(instr)[2:].zfill(8))
        # TODO: add def-use analysis here
        funcNodes.append(node)
    return funcNodes

def getEdges(funcNodes: List[CfgNode]) -> List[CfgEdge]:
    funcEdges = []
    for indx, node in enumerate(funcNodes[:-1]):
        if node.address == START:
            edge = CfgEdge(node.nodenum, funcNodes[indx+1].nodenum)
            funcEdges.append(edge)
        else:
            xrefsFrom = [xref for xref in idautils.XrefsFrom(node.address, 0)]
            for xref in xrefsFrom:
                validEdgeAddress = xref.to
                validEdgeNodes = [node.nodenum for node in funcNodes if node.address==validEdgeAddress]
                if validEdgeNodes:
                    edge = CfgEdge(node.nodenum, validEdgeNodes[0])
                    funcEdges.append(edge)
    return funcEdges
