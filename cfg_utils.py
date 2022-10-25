import idautils
import idc
import re
from models.base_classes import *
from cfg_constants import *

def getNodes(func) -> List[CfgNode]:
    instructions = [instr for instr in idautils.Heads(func.start_ea, func.end_ea)]
    funcNodes = []
    startNode = CfgNode(0, START_NODE_LABEL)
    funcNodes.append(startNode)
    for indx, instr in enumerate(instructions):
        defList, useList = getDefUseLists(instr)
        node = CfgNode(nodenum = indx + 1, address = instr, label = hex(instr)[2:].zfill(8), defList=defList, useList=useList)
        funcNodes.append(node)
    return funcNodes


def getEdges(funcNodes: List[CfgNode]) -> List[CfgEdge]:
    funcEdges = []
    for indx, node in enumerate(funcNodes[:-1]):
        if node.address == START_NODE_LABEL:
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


'''
get_operand_type:
0: o_void     = ida_ua.o_void      # No Operand                           ----------
1: o_reg      = ida_ua.o_reg       # General Register (al,ax,es,ds...)    reg
2: o_mem      = ida_ua.o_mem       # Direct Memory Reference  (DATA)      addr
3: o_phrase   = ida_ua.o_phrase    # Memory Ref [Base Reg + Index Reg]    phrase
4: o_displ    = ida_ua.o_displ     # Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
5: o_imm      = ida_ua.o_imm       # Immediate Value                      value
6: o_far      = ida_ua.o_far       # Immediate Far Address  (CODE)        addr
7: o_near     = ida_ua.o_near      # Immediate Near Address (CODE)        addr
o_idpspec0 = ida_ua.o_idpspec0  # Processor specific type
o_idpspec1 = ida_ua.o_idpspec1  # Processor specific type
o_idpspec2 = ida_ua.o_idpspec2  # Processor specific type
o_idpspec3 = ida_ua.o_idpspec3  # Processor specific type
o_idpspec4 = ida_ua.o_idpspec4  # Processor specific type
o_idpspec5 = ida_ua.o_idpspec5  # Processor specific type
                                # There can be more processor specific types

get_operand_value:
operand is an immediate value  => immediate value
operand has a displacement     => displacement
operand is a direct memory ref => memory address
operand is a register          => register number
operand is a register phrase   => phrase number
otherwise                      => -1
'''

def getDefUseLists(instruction_address) -> Tuple[List[str], List[str]]:
    mnemonic = idc.print_insn_mnem(instruction_address)
    operands = []
    op_count = 0

    while(True):
        next_operand = idc.print_operand(instruction_address, op_count)
        if next_operand:
            operands.append(next_operand)
            op_count = op_count + 1
        else:
            break
    
    defList = set()
    useList = set()

    for operand_number in range(len(operands)):
        operand_type = idc.get_operand_type(instruction_address, operand_number)
        operand_value = idc.get_operand_value(instruction_address, operand_number)
        
        if operand_type==1 or operand_type==3 or operand_type==4 or operand_value==-1:
            operand_value = operands[operand_number]
        
        elif operand_type==2 or operand_type==5 or operand_type==6 or operand_type==7:
            if operand_type == 5:
                if 'offset' in operands[operand_number]:
                    operand_value = '[' + hex(operand_value) + ']'
                else:
                    # When it is actually a direct value rather than a data pointer
                    operand_value = '0x' + hex(operand_value)[2:][-8:]
            else:
                operand_value = '[' + hex(operand_value) + ']'
        
        else:
            operand_value = operands[operand_number]

        if PUSH in mnemonic:
            defList.add(ESP)
            defList.add(ESP_ADDR)
            useList.add(ESP)
        if POP in mnemonic:
            defList.add(ESP)
            useList.add(ESP_ADDR)
            useList.add(ESP)
        if CALL in mnemonic:
            defList.add(EAX)
            defList.add(ESP)
            useList.add(ESP)
        if LEAVE in mnemonic:
            defList.add(ESP)
            defList.add(EBP)
            useList.add(ESP_ADDR)
            useList.add(ESP)

        if mnemonic in ZERO_FLAG_USERS:
            useList.add(ZF)
        if mnemonic in CARRY_FLAG_USERS:
            useList.add(CF)
        if mnemonic in ALL_FLAG_DEF_MNEMONICS:
            defList.add(ZF)
            defList.add(SF)
            defList.add(OF)
            defList.add(CF)
        if INC in mnemonic:
            defList.add(ZF)
            defList.add(SF)
            defList.add(OF)

        if '[' in operand_value:
            extracted_brackets = extractBracketParams(operand_value)
            if extracted_brackets:
                operand_value = extracted_brackets
            if '+' in operand_value or operand_type == 3:
                registers_in_opr = []
                if (len(operand_value.split('+')) == 1 or len(operand_value.split('+')) == 2):
                    registers_in_opr.append(operand_value.split('+')[0].strip('[').strip(']'))
                elif (len(operand_value.split('+')) == 3):
                    registers_in_opr.append(operand_value.split('+')[0].strip('['))
                    registers_in_opr.append(operand_value.split('+')[1])
                if operand_number == 0:
                    if mnemonic not in NON_DEF_MNEMONICS:
                        defList.add(str(operand_value).upper())
                    for register in registers_in_opr:
                        useList.add(str(register).upper())
                else:
                    for register in registers_in_opr:
                        useList.add(str(register).upper())
                    if mnemonic not in NON_USE_MNEMONICS:
                        useList.add(str(operand_value).upper())
            else:
                useList.add(operand_value)
                if operand_number == 0:
                    if CALL not in mnemonic and mnemonic not in NON_DEF_MNEMONICS:
                        defList.add(operand_value)
                    if mnemonic in MOV and operand_value in useList:
                        useList.remove(operand_value)
                if mnemonic in JUMP_INSTRUCTIONS:
                    if operand_value in defList:
                        defList.remove(operand_value)
                    if operand_value in useList:
                        useList.remove(operand_value)
                if operand_type == 5:
                    if PUSH in mnemonic:
                        if operand_value in useList:
                            useList.remove(operand_value)
        else:
            if operand_type == 1:
                if operand_number == 0:
                    if MOV not in mnemonic and mnemonic not in NON_USE_MNEMONICS:
                        useList.add(str(operand_value).upper())
                    if mnemonic not in NON_DEF_MNEMONICS:
                        defList.add(str(operand_value).upper())
                else:
                    useList.add(str(operand_value).upper())
    return list(defList), list(useList)

def extractBracketParams(input_string: str) -> str:
    brackets_pattern = r"\[[^\]]*\]"
    matches = re.findall(brackets_pattern, input_string)
    if matches:
        return matches[0]
    return ''
