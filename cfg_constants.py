from sre_constants import JUMP


START_NODE_LABEL = "Start"

EAX = 'EAX'
ESP = 'ESP'
ESP_ADDR = '[ESP]'
EBP = 'EBP'

ZF = 'ZF'
CF = 'CF'
OF = 'OF'
SF = 'SF'
ALL_FLAGS = 'CF,ZF,SF,OF'

# Mnemonics
MOV = 'mov'
PUSH = 'push'
POP = 'pop'
ZERO_FLAG_USERS = ['jz', 'jnz', 'jbe', 'jne', 'ja', 'je', 'jg', 'jle','jna', 'jnbe','jng','jnle','jpe']
CARRY_FLAG_USERS = ['jbe', 'jnbe', 'ja', 'jae', 'jnae', 'jna', 'jnb', 'jb', 'jc', 'jnc',]
CALL = 'call'
LEA = 'lea'
INC = 'inc'
LEAVE = 'leave'

# Mnemonics Lists
NON_DEF_MNEMONICS = ['cmp', 'test', 'push', 'jz']
NON_USE_MNEMONICS = ['pop', 'lea', 'mov']
ALL_FLAG_DEF_MNEMONICS = ['cmp', 'sub', 'add', 'xor', 'or', 'test']
JUMP_INSTRUCTIONS = ['jmp', 'ja', 'jae', 'jb', 'jbe', 'je', 'jg', 'jge', 'jl','jle','jna','jnae','jnb','jnbe','jnc','jne','jng','jnge','jnl','jnle','jno','jnp','jns','jnz','jo','jp','jpe','jpo','js','jz']