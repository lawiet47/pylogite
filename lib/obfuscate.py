from instructions import *
from asmutils import *
from mpe import *


class OBFS:
    def __init__(self, iterations, mpe, pasm, target_rva):
        self.iterations = iterations
        self.mpe = mpe
        self.pasm = pasm
        self.last_garbage_bytes = None
        self.target_rva = target_rva

    def set_iterations(self, iterations):
        self.iterations = iterations

    def set_target_rva(self, target_rva):
        self.target_rva = target_rva

    def opcode_short_to_near(self, branch_bytes):
        btype = self.pasm.get_branch_type(branch_bytes)
        if btype == self.pasm.BRANCH_TYPE.JCC_NEAR:
            return branch_bytes[0:2]
        elif btype == self.pasm.BRANCH_TYPE.JCC_SHORT:
            return bytearray(b'\x0f' + (branch_bytes[0] + 0x10).to_bytes(1, byteorder='little', signed=False))
        elif btype == self.pasm.BRANCH_TYPE.JMP_SHORT:
            return bytearray(b'\xe9')
        elif btype == self.pasm.BRANCH_TYPE.CALL:
            return branch_bytes[0:1]
        elif btype == self.pasm.BRANCH_TYPE.JMP_NEAR:
            return branch_bytes[0:1]
        elif btype == self.pasm.BRANCH_TYPE.LOOPCC or btype == self.pasm.BRANCH_TYPE.JXCC_SHORT:
            logging.log(ERROR, "Unimplemented branch found: {0}".format(branch_bytes))
            sys.exit(0)

    def uniform_jmps(self, rbytes):

        if len(self.pasm.jmp_array) > 0:

            for i in range(0, len(self.pasm.jmp_array)):
                if self.pasm.jmp_array[i].type == self.pasm.BRANCH_TYPE.JCC_SHORT:
                    self.pasm.jmp_array[i].size = 6
                    self.pasm.jmp_array[i].type = self.pasm.BRANCH_TYPE.JCC_NEAR
                elif self.pasm.jmp_array[i].type == self.pasm.BRANCH_TYPE.JMP_SHORT:
                    self.pasm.jmp_array[i].size = 5
                    self.pasm.jmp_array[i].type = self.pasm.BRANCH_TYPE.JMP_NEAR
                else:
                    continue

                added_bytes = (self.pasm.jmp_array[i].size - self.pasm.jmp_array[i].oldsize)
                # Index jmp address
                rindex = self.pasm.jmp_array[i].addr
                for j in range(0, len(self.pasm.jmp_array)):
                    if added_bytes == 0:
                        continue

                    # Forward jmps
                    if self.pasm.jmp_array[j].addr < self.pasm.jmp_array[j].label:
                        # Current jmp is above the index jmp
                        if rindex > self.pasm.jmp_array[j].addr:
                            if rindex < self.pasm.jmp_array[j].label:
                                self.pasm.jmp_array[j].offset += added_bytes
                            elif rindex > self.pasm.jmp_array[j].label:
                                pass
                            else:
                                pass
                        # Current jmp is below the index jmp
                        elif rindex < self.pasm.jmp_array[j].addr:
                            self.pasm.jmp_array[j].addr += added_bytes
                        # The current jmp is equal to the index jmp
                        else:
                            pass
                    # Backward jmps
                    elif self.pasm.jmp_array[j].addr > self.pasm.jmp_array[j].label:
                        # Current jmp is above the index jmp
                        if rindex > self.pasm.jmp_array[j].addr:
                            pass
                        # Current jmp is below the index jmp
                        elif rindex < self.pasm.jmp_array[j].addr:
                            if rindex > self.pasm.jmp_array[j].label:
                                self.pasm.jmp_array[j].offset -= added_bytes
                            elif rindex < self.pasm.jmp_array[j].label:
                                pass
                            else:
                                self.pasm.jmp_array[j].offset -= added_bytes
                            self.pasm.jmp_array[j].addr += added_bytes
                        # The current jmp is equal to the index jmp
                        else:
                            self.pasm.jmp_array[j].offset -= added_bytes
                            #sys.exit(0)

                    # Self jmps
                    else:
                        logging.log(ERROR, "Found self jmp instruction Exiting...")
                        sys.exit(0)

                    self.pasm.jmp_array[j].label = (self.pasm.jmp_array[j].addr + self.pasm.jmp_array[j].offset + self.pasm.jmp_array[j].size)
                    self.pasm.jmp_array[j].opcode = self.opcode_short_to_near(self.pasm.jmp_array[j].bytes)
                    self.pasm.jmp_array[j].bytes = bytearray(self.pasm.jmp_array[j].opcode + self.pasm.jmp_array[j].offset.to_bytes(4, byteorder='little', signed=True))

                self.adjust_movs(rindex, added_bytes)

            for x in range(0, len(self.pasm.jmp_array)):
                rbytes = insert_bytes(rbytes, (self.pasm.jmp_array[x].addr + self.pasm.jmp_array[x].oldsize), self.pasm.jmp_array[x].bytes[self.pasm.jmp_array[x].oldsize:])
                rbytes = replace_bytes(rbytes, self.pasm.jmp_array[x].addr, self.pasm.jmp_array[x].oldsize, self.pasm.jmp_array[x].bytes)

        return rbytes

    def fix_jmps(self, rbytes, rindex, added_bytes):

        for j in range(0, len(self.pasm.jmp_array)):
            if len(added_bytes) == 0:
                continue

            # Forward jmps
            if self.pasm.jmp_array[j].addr < self.pasm.jmp_array[j].label:
                # Inserted below the jmp
                if rindex > self.pasm.jmp_array[j].addr:
                    if rindex < self.pasm.jmp_array[j].label:
                        self.pasm.jmp_array[j].offset += len(added_bytes)
                    elif rindex > self.pasm.jmp_array[j].label:
                        pass
                    else:
                        self.pasm.jmp_array[j].offset += len(added_bytes)
                # Inserted above the jmp
                elif rindex <= self.pasm.jmp_array[j].addr:
                    self.pasm.jmp_array[j].addr += len(added_bytes)
                # Inserted onto the jmp (should not happen)
                #else:
                #    print("Rindex: {0} == Jmp_Addr: {1}".format(hex(rindex), hex(self.pasm.jmp_array[j].addr)))
                #    sys.exit(0)
            # Backward jmps
            elif self.pasm.jmp_array[j].addr > self.pasm.jmp_array[j].label:
                # Inserted below the jmp
                if rindex > self.pasm.jmp_array[j].addr:
                    pass
                # Inserted above the jmp
                elif rindex <= self.pasm.jmp_array[j].addr:
                    if rindex > self.pasm.jmp_array[j].label:
                        self.pasm.jmp_array[j].offset -= len(added_bytes)
                    elif rindex < self.pasm.jmp_array[j].label:
                        pass
                    else:
                        self.pasm.jmp_array[j].offset -= len(added_bytes)
                    self.pasm.jmp_array[j].addr += len(added_bytes)
                # Inserted onto the jmp (should never happen)
                #else:
                #    print("Rindex: {0} == Jmp_Addr: {1}".format(hex(rindex), hex(self.pasm.jmp_array[j].addr)))
                #    sys.exit(0)

            # Self jmps
            else:
                logging.log(ERROR, "Found self jmp instruction Exiting...")
                sys.exit(0)

            self.pasm.jmp_array[j].label = (self.pasm.jmp_array[j].addr + self.pasm.jmp_array[j].offset + self.pasm.jmp_array[j].size)
            self.pasm.jmp_array[j].opcode = self.opcode_short_to_near(self.pasm.jmp_array[j].bytes)
            self.pasm.jmp_array[j].bytes = bytearray(self.pasm.jmp_array[j].opcode + self.pasm.jmp_array[j].offset.to_bytes(4, byteorder='little',signed=True))

        self.adjust_movs(rindex, len(added_bytes))
        for j in range(0, len(self.pasm.jmp_array)):
            rbytes = replace_bytes(rbytes, self.pasm.jmp_array[j].addr, len(self.pasm.jmp_array[j].bytes), self.pasm.jmp_array[j].bytes)

        return rbytes

    def adjust_movs(self, rindex, added_bytes):
        for j in range(0, len(self.pasm.mov_array)):
            if rindex <= self.pasm.mov_array[j].addr:
                self.pasm.mov_array[j].addr += added_bytes

    def fix_movs(self, rbytes):
        for j in range(0, len(self.pasm.mov_array)):
            rbytes = replace_bytes(rbytes, self.pasm.mov_array[j].addr, len(self.pasm.mov_array[j].bytes), self.pasm.mov_array[j].bytes)
        return rbytes

    def obfuscate_movs(self):
        if len(self.pasm.mov_array) > 0:
            for i in range(0, len(self.pasm.mov_array)):
                src = self.pasm.mov_array[i].immval
                dst = self.pasm.mov_array[i].dst
                delta = get_random_bytes(self.pasm.mov_array[i].immval_size)
                src ^= delta
                op = "MOV {DST},{SRC};"
                op = op.replace("{DST}", dst)
                op = op.replace("{SRC}", hex(src))
                self.pasm.mov_array[i].bytes = self.pasm.assemble(op)
                self.pasm.mov_array[i].size = len(self.pasm.mov_array[i].bytes)
                self.pasm.mov_array[i].immval = src
                #self.pasm.mov_array[i].immval_size = (src.bit_length()+7)//8

                iteration = random.randint(0,3)
                xop=""
                for x in range(0, iteration):
                    src = delta
                    delta = get_random_bytes(self.pasm.mov_array[i].immval_size)
                    src ^= delta
                    op = "XOR {DST},{SRC};"
                    op = op.replace("{DST}", dst)
                    op = op.replace("{SRC}", hex(src))
                    xop += op

                op = "XOR {DST},{SRC};"
                op = op.replace("{DST}", dst)
                op = op.replace("{SRC}", hex(delta))
                xop += op
                self.pasm.mov_array[i].postbytes = self.pasm.assemble(xop)


    @staticmethod
    def dice_roll():
        return random.randint(1, 6)

    @staticmethod
    def create_garbage_asm():
        RANDOM_INST = ""
        if OBFS.dice_roll() % 2 == 0:
            RANDOM_INST = GARBAGE_ASM[random.randint(0, len(GARBAGE_ASM) - 1)]
        else:
            x = ""
            if OBFS.dice_roll() % 2 == 0:
                for i in range(1, OBFS.dice_roll()):
                    x += x64_REGISTER_MATH[random.randint(0, len(x64_REGISTER_MATH) - 1)]
                safeguard = get_safeguard()
                x = safeguard.replace("{A}", x)
                RANDOM_INST = x
            else:
                if OBFS.dice_roll() % 2 == 0:
                    x += JCC_INSTRUCTION[random.randint(0, len(JCC_INSTRUCTION) - 1)]
                else:
                    x += JMP_INSTRUCTION[random.randint(0, len(JMP_INSTRUCTION) - 1)]
                RANDOM_INST = x

        x64_random_reg = x64_REGISTERS[random.randint(0, len(x64_REGISTERS) - 1)]
        x128_random_reg = x128_REGISTERS[random.randint(0, len(x128_REGISTERS) - 1)]
        random_label = get_random_label()

        RANDOM_INST = RANDOM_INST.replace("{R64}", x64_random_reg)
        RANDOM_INST = RANDOM_INST.replace("{R128}", x128_random_reg)
        RANDOM_INST = RANDOM_INST.replace("{IMM8}", hex(get_random_bytes(1)))
        RANDOM_INST = RANDOM_INST.replace("{IMM16}", hex(get_random_bytes(2)))
        RANDOM_INST = RANDOM_INST.replace("{IMM32}", hex(get_random_bytes(4)))
        RANDOM_INST = RANDOM_INST.replace("{IMM64}", hex(get_random_bytes(8)))
        RANDOM_INST = RANDOM_INST.replace("{L}", random_label)

        return RANDOM_INST

    @staticmethod
    def get_random_junk_inst():
        RANDOM_INST = OBFS.create_garbage_asm()
        while "{G}" in RANDOM_INST:
            RANDOM_INST = RANDOM_INST.replace("{G}", OBFS.create_garbage_asm())
        return RANDOM_INST.encode('utf-8')

    def mix_junk_to_bytes(self):
        for i in range(0, self.iterations):
            # Generate garbage assembly with uniform jmps
            self.last_garbage_bytes = bytearray(self.pasm.assemble(OBFS.get_random_junk_inst()))
            self.pasm.find_relative_branches(self.last_garbage_bytes)
            self.last_garbage_bytes = self.uniform_jmps(self.last_garbage_bytes)

            # Find the relative branches in the shellcode bytes
            self.pasm.find_relative_branches(self.mpe.shellcode_bytes)

            #self.mpe.shellcode_bytes = self.uniform_jmps(self.mpe.shellcode_bytes)

            # Generate an insertable index in the shellcode bytearray
            valid_indexes = self.get_valid_index_for_mixing(self.mpe.shellcode_bytes)
            rindex = valid_indexes[random.randint(0, len(valid_indexes) - 1)]
            # Insert the bytes and fix the shellcode bytearray
            self.mpe.shellcode_bytes = insert_bytes(self.mpe.shellcode_bytes, rindex, self.last_garbage_bytes)
            self.mpe.shellcode_bytes = self.fix_jmps(self.mpe.shellcode_bytes, rindex, self.last_garbage_bytes)

        return self.mpe.shellcode_bytes

    def get_valid_index_for_mixing(self, rbytes):
        valid_indexes = []
        instructions = self.pasm.disassemble(rbytes)
        for i in range(0, len(instructions)):
            if not (instructions[i].mnemonic.startswith("j") or instructions[i].mnemonic == "call"):
                valid_indexes.append(instructions[i].address)
        return valid_indexes
