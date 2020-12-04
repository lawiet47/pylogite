from capstone import *
from keystone import *
import binascii
from colorama import *
import colorama
from helpers import *


class ASM_UTILS:
    class JMP_INST:
        def __init__(self, mnemonic=None, bytes=None, label=None, size=None, type=None, opcode=None, offset=None, addr=None, prebytes=None):
            self.bytes = bytes
            self.size = size
            self.oldsize = size
            self.type = type
            self.opcode = opcode
            self.offset = offset
            self.addr = addr
            self.label = label
            self.prebytes = prebytes
            self.mnemonic = mnemonic

    class MOV_INST:
        def __init__(self, mnemonic=None, size=None, immval=None, dst=None, immval_size=None, addr=None, postbytes=None, bytes=None):
            self.addr = addr
            self.size = size
            self.immval = immval
            self.postbytes = postbytes
            self.mnemonic = mnemonic
            self.immval_size = immval_size
            self.dst = dst
            self.bytes = bytes
            self.oldsize = size

    class BRANCH_TYPE:
        CALL = 0
        JMP_SHORT = 1
        JCC_SHORT = 2
        JCC_NEAR = 3
        JMP_NEAR = 4
        JXCC_SHORT = 5
        LOOPCC = 6

    def __init__(self):
        self.assembler = Ks(KS_ARCH_X86, KS_MODE_64)
        self.disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
        self.jmp_array = []
        self.mov_array = []

    def disassemble(self, rbytes):
        if len(rbytes) > 0:
            instructions = []
            for i in self.disassembler.disasm(rbytes, 0):
                instructions.append(i)
            return instructions
        logging.log(ERROR, "Cannot disassemble bytes with 0 size")
        sys.exit(0)

    def assemble(self, rbytes):
        if len(rbytes) > 0:
            try:
                encoding, count = self.assembler.asm(rbytes)
                generated_asm = bytes(encoding)
            except KsError as e:
                print("[!] Assembly Error: {0}: {1}".format(e, rbytes))
                sys.exit(0)
            return generated_asm
        logging.log(ERROR, "Cannot assemble a buffer with 0 size")
        sys.exit(0)

    def find_relative_branches(self, rbytes):
        branches = []
        for i in self.disassemble(rbytes):
            jmp_label = to_integer(i.op_str)
            if i.mnemonic.startswith("j") or i.mnemonic == "call":
                if jmp_label is not None:
                    branch = self.JMP_INST()
                    branch.addr = i.address
                    branch.mnemonic = i.mnemonic
                    branch.type = self.get_branch_type(i.bytes)
                    branch.opcode, branch.offset = self.unpack_jmp(i.bytes)
                    branch.size = len(i.bytes)
                    branch.bytes = bytearray(i.bytes)
                    branch.prebytes = bytearray(b'')
                    branch.label = jmp_label
                    branch.oldsize = branch.size
                    branches.append(branch)
        self.jmp_array = branches

    def find_immediate_movs(self, rbytes):
        movs = []
        for i in self.disassemble(rbytes):
            if i.mnemonic.startswith("mov"):
                dst, imm_val = i.op_str.split(', ')
                if imm_val is None:
                    logging.log(ERROR, "Could not get dst or imm_val from opcode: {0} {1}".format(i.mnemonic, i.op_str))
                    sys.exit(0)
                imm_val = to_integer(imm_val)
                if imm_val is not None:
                    mov = self.MOV_INST()
                    mov.addr = i.address
                    mov.mnemonic = i.mnemonic
                    mov.size = len(i.bytes)
                    mov.oldsize = mov.size
                    mov.bytes = bytearray(i.bytes)
                    mov.postbytes = bytearray(b'')
                    mov.immval = imm_val
                    mov.immval_size = (imm_val.bit_length()+7)//8
                    mov.dst = dst
                    # TODO: Xor operation doesn't support 64 immediate values so we exclude it
                    if mov.immval_size != 8 and mov.immval_size != 0 and mov.immval <= 0x7fffffff:
                        movs.append(mov)
        self.mov_array = movs

    def unpack_jmp(self, jmp_bytes):
        branch_type = self.get_branch_type(jmp_bytes)
        opcode_offset = 0
        if branch_type == self.BRANCH_TYPE.JCC_SHORT or branch_type == self.BRANCH_TYPE.JMP_SHORT \
                or branch_type == self.BRANCH_TYPE.JMP_NEAR or branch_type == self.BRANCH_TYPE.CALL \
                or branch_type == self.BRANCH_TYPE.JXCC_SHORT or branch_type == self.BRANCH_TYPE.LOOPCC:
            opcode_offset = 1
        elif branch_type == self.BRANCH_TYPE.JCC_NEAR:
            opcode_offset = 2
        jmp_opcode = bytearray(jmp_bytes[0:opcode_offset])
        jmp_offset = jmp_bytes[opcode_offset:]
        # jmp_opcode = int.from_bytes(jmp_opcode, byteorder='little', signed=False)
        jmp_offset = int.from_bytes(jmp_offset, byteorder='little', signed=True)

        return jmp_opcode, jmp_offset

    def get_branch_type(self, jmp_bytes):
        if 0x70 < jmp_bytes[0] < 0x80:
            return self.BRANCH_TYPE.JCC_SHORT
        elif jmp_bytes[0] == 0x0f:
            return self.BRANCH_TYPE.JCC_NEAR
        elif jmp_bytes[0] == 0xeb:
            return self.BRANCH_TYPE.JMP_SHORT
        elif jmp_bytes[0] == 0xe9:
            return self.BRANCH_TYPE.JMP_NEAR
        elif jmp_bytes[0] == 0xe8:
            return self.BRANCH_TYPE.CALL
        elif 0xe0 <= jmp_bytes[0] <= 0xe2:
            return self.BRANCH_TYPE.LOOPCC
        elif jmp_bytes[0] == 0xe3:
            return self.BRANCH_TYPE.JXCC_SHORT

    def print_disasm(self, rbytes):
        colorama.init()
        instructions = self.disassemble(rbytes)
        jmp_index = 0
        if len(instructions) > 0:
            for i in range(0, len(instructions)):
                inst_addr = instructions[i].address
                inst_opcode = binascii.hexlify(instructions[i].bytes).decode('utf-8')
                mnemonic = instructions[i].mnemonic
                opstr = instructions[i].op_str
                jmp_target = to_integer(opstr)
                valid_jump = False
                if mnemonic.startswith('j') or mnemonic == "call":
                    if mnemonic.startswith('j'):
                        msg_color = Fore.LIGHTMAGENTA_EX
                    else:
                        msg_color = Fore.CYAN
                    disasm_str = "{0}{1}:\t{2:<30}\t\t{3:>1} {4}{5}".format(msg_color, hex(inst_addr), inst_opcode,
                                                                               mnemonic, opstr, Style.RESET_ALL)
                    if jmp_target is not None:
                        for j in range(0, len(instructions)):
                            if jmp_target == instructions[j].address:
                                valid_jump = True
                                msg_color = Fore.GREEN
                                disasm_str += (
                                    "\n  |\n  `---> {0} [BRANCHES] {1} {2} {3}{4}".format(msg_color, binascii.hexlify(
                                        instructions[j].bytes).decode('utf-8'),
                                                                                          instructions[j].mnemonic,
                                                                                          instructions[j].op_str,
                                                                                          Style.RESET_ALL))
                        if not valid_jump:
                            msg_color = Fore.RED
                            disasm_str += (
                                "\n  |\n  `---> {0} [INVALID] (No such address) {1} {2}".format(msg_color,
                                                                                                hex(jmp_target),
                                                                                                Style.RESET_ALL))
                    jmp_index += 1
                else:
                    msg_color = ""
                    disasm_str = "{0}{1}:\t{2:<30}\t\t{3:>1} {4}{5}".format(msg_color, hex(inst_addr), inst_opcode,
                                                                               mnemonic, opstr, Style.RESET_ALL,)
                print(disasm_str)
