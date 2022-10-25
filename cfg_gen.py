import idaapi
import ida_funcs
from models.base_classes import *
from cfg_utils import *

class CfgPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Author: Shubham Pharande"
    help = "This plugin generates a DOT graph of the CFG of all functions in the binary, along with an approximate def-use and data definition flow"
    wanted_name = "Static analysis graph generator"
    wanted_hotkey = "Alt-F2"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg=None):
        func_list = [func for func in idautils.Functions()]
        for func_entry in func_list:
            funcNodes = getNodes(ida_funcs.get_func(func_entry))
            funcEdges = getEdges(funcNodes)
            digraph = Digraph(nodes=funcNodes, edges=funcEdges)
            digraph.generateDDList()
            dotFileName = '/nethome/spharande3/shared/a3/graphs/' + str(hex(func_entry)[2:]) + '.dot'
            with open(dotFileName, 'w') as dotFile:
                dotFile.write(str(digraph))
        return idaapi.PLUGIN_UNL

    def term(self):
        pass


def PLUGIN_ENTRY():
    return CfgPlugin()

if __name__ == "__main__":
    cfg = CfgPlugin()
    cfg.run()
