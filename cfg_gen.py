import idaapi
import idautils
import ida_funcs
import idc
import ida_ua
from models.base_classes import *
from cfg_utils import *


class CfgPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "This is a comment"
    help = "This plugin generates a DOT graph of the CFG of all functions in a binary"
    wanted_name = "CFG generation plugin"
    wanted_hotkey = "Alt-F2"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg=None):
        '''
        Testing for getNodes with WinMain
        funcNodes = getNodes(ida_funcs.get_func(0x0040297D))
        print(funcNodes[0], funcNodes[1], funcNodes[2])
        '''
        funcNodes = getNodes(ida_funcs.get_func(0x00402aaf))
        funcEdges = getEdges(funcNodes)
        defList, useList = getDefUseLists(0x0040144A)
        # func_list = [func for func in idautils.Functions()]
        # for func_entry in func_list:
            # funcNodes = getNodes(ida_funcs.get_func(func_entry))
        # TODO: Fill stuff after this - writing to new file for each function.
        digraph = Digraph(nodes=funcNodes, edges=funcEdges)
        # print(digraph)
        return idaapi.PLUGIN_UNL

    def term(self):
        pass

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
    print(mnemonic)
    print(operands)
    for i in range(len(operands)):
        operand_type = idc.get_operand_type(instruction_address, i)
        operand_value = idc.get_operand_value(instruction_address, i)
        if operand_type==1 or operand_type==3 or operand_type==4 or operand_value==-1:
            print(operand_value)
            operand_value = operands[i]
        elif operand_type==2 or operand_type==5 or operand_type==6 or operand_type==7:
            if operand_type == 5:
                if 'offset' in operands[i]:
                    operand_value= '[' + hex(operand_value) + ']'
                else:
                    # When it is actually a direct value rather than a data pointer
                    operand_value= operand_value
            else:
                operand_value= '[' + hex(operand_value) + ']'
        else:
            operand_value = operands[i]
        # TODO: do something about the displacement (type=4) - name to number
        # TODO: Handling stack params
        # TODO: Handling flags

        print(operand_type)
        print(operand_value)

    defList = []
    useList = []
    return defList, useList

def PLUGIN_ENTRY():
    return CfgPlugin()

if __name__ == "__main__":
    cfg = CfgPlugin()
    cfg.run()
