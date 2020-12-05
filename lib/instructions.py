import random


def get_random_bytes(bytesize):
    if bytesize == 1:
        return get_random_imm8()
    elif bytesize == 2:
        return get_random_imm16()
    elif bytesize == 4:
        return get_random_imm32()
    elif bytesize == 8:
        return get_random_imm64()
    return 0


def get_random_imm8():
    return random.getrandbits(8*1)


def get_random_imm16():
    return random.getrandbits(8*2)


def get_random_imm32():
    return random.getrandbits(8*4)&0x7fffffff


def get_random_imm64():
    return random.getrandbits(8*8)&0x7fffffffffffffff


def get_random_label():
    random_label = ""
    for i in range(0, 9):
        random_label += asm_label_alphabet[random.randint(0, len(asm_label_alphabet) - 1)]
    return random_label


def get_safeguard():
    return SAFEGUARD_REGS_SAVE[random.randint(0, len(SAFEGUARD_REGS_SAVE) - 1)] + ";{A};" + SAFEGUARD_REGS_RESTORE[random.randint(0, len(SAFEGUARD_REGS_RESTORE) - 1)]


asm_label_alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Only the x64 registers are implemented at the time
# TODO: implement 8/16/32/128 bit registers later
x64_REGISTERS = [
    'RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI'
]

x128_REGISTERS = [
    'XMM0', 'XMM1', 'XMM2', 'XMM3', 'XMM4', 'XMM5', 'XMM6', 'XMM7',
    'XMM8', 'XMM9', 'XMM10', 'XMM11', 'XMM12', 'XMM13', 'XMM14', 'XMM15'
]

# Register save operations
SAFEGUARD_REGS_SAVE = [
    "PUSH {R64};",
    "LEA RSP,[RSP-8]; MOV [RSP], {R64};",
    "SUB RSP, 0x8; MOV [RSP], {R64};"
]

# Register restore operations
SAFEGUARD_REGS_RESTORE = [
    "POP {R64};",
    "MOV {R64}, [RSP]; ADD RSP,0x8;",
    "LEA {R64}, [RSP + 0x4];MOV {R64},[{R64} - 0x4]; ADD RSP,0x8;",
    "MOV {R64}, [RSP]; LEA RSP,[RSP+8];"
]

JCC_INSTRUCTION = [
    "JNE {L};JE {L}; {G};CALL [{R64}+{IMM8}];{L}:;",
    "JE {L};JNE {L}; {G};CALL [{R64}+{IMM8}];{L}:;",
    "JZ {L};JNZ {L}; {G};CALL [{R64}+{IMM8}];{L}:;",
    "JA {L};JBE {L}; {G};CALL [{R64}+{IMM8}];{L}:;",
    "JAE {L};JB {L}; {G};CALL [{R64}+{IMM8}];{L}:;",
    "JGE {L};JL {L}; {G};CALL [{R64}+{IMM8}];{L}:;",
    "JLE {L};JG {L}; {G};CALL [{R64}+{IMM8}];{L}:;",
    "JP {L};JNP {L}; {G};CALL [{R64}+{IMM8}];{L}:;",
    "JS {L};JNS {L}; {G};CALL [{R64}+{IMM8}];{L}:;",
    "JNE {L};JE {L}; {G};CALL [{R64}+{IMM16}];{L}:;",
    "JE {L};JNE {L}; {G};CALL [{R64}+{IMM16}];{L}:;",
    "JZ {L};JNZ {L}; {G};CALL [{R64}+{IMM16}];{L}:;",
    "JA {L};JBE {L}; {G};CALL [{R64}+{IMM16}];{L}:;",
    "JAE {L};JB {L}; {G};CALL [{R64}+{IMM16}];{L}:;",
    "JGE {L};JL {L}; {G};CALL [{R64}+{IMM16}];{L}:;",
    "JLE {L};JG {L}; {G};CALL [{R64}+{IMM16}];{L}:;",
    "JP {L};JNP {L}; {G};CALL [{R64}+{IMM16}];{L}:;",
    "JS {L};JNS {L}; {G};CALL [{R64}+{IMM16}];{L}:;",
    "JNE {L};JE {L}; {G};CALL [{R64}+{IMM32}];{L}:;",
    "JE {L};JNE {L}; {G};CALL [{R64}+{IMM32}];{L}:;",
    "JZ {L};JNZ {L}; {G};CALL [{R64}+{IMM32}];{L}:;",
    "JA {L};JBE {L}; {G};CALL [{R64}+{IMM32}];{L}:;",
    "JAE {L};JB {L}; {G};CALL [{R64}+{IMM32}];{L}:;",
    "JGE {L};JL {L}; {G};CALL [{R64}+{IMM32}];{L}:;",
    "JLE {L};JG {L}; {G};CALL [{R64}+{IMM32}];{L}:;",
    "JP {L};JNP {L}; {G};CALL [{R64}+{IMM32}];{L}:;",
    "JS {L};JNS {L}; {G};CALL [{R64}+{IMM32}];{L}:;",
    "JNE {L};JE {L}; {G};CALL [{R64}+{IMM64}];{L}:;",
    "JE {L};JNE {L}; {G};CALL [{R64}+{IMM64}];{L}:;",
    "JZ {L};JNZ {L}; {G};CALL [{R64}+{IMM64}];{L}:;",
    "JA {L};JBE {L}; {G};CALL [{R64}+{IMM64}];{L}:;",
    "JAE {L};JB {L}; {G};CALL [{R64}+{IMM64}];{L}:;",
    "JGE {L};JL {L}; {G};CALL [{R64}+{IMM64}];{L}:;",
    "JLE {L};JG {L}; {G};CALL [{R64}+{IMM64}];{L}:;",
    "JP {L};JNP {L}; {G};CALL [{R64}+{IMM64}];{L}:;",
    "JS {L};JNS {L}; {G};CALL [{R64}+{IMM64}];{L}:;",
]

JMP_INSTRUCTION = [
    "JNE {L};JMP {L}; {G};CALL [{R64}+{IMM8}];{L}:;",
    "JNZ {L};JMP {L}; {G};CALL [{R64}+{IMM8}];{L}:;",
    "JA {L};JMP {L}; {G};CALL [{R64}+{IMM8}];{L}:;",
    "JAE {L};JMP {L}; {G};CALL [{R64}+{IMM8}];{L}:;",
    "JGE {L};JMP {L}; {G};CALL [{R64}+{IMM8}];{L}:;",
    "JLE {L};JMP {L}; {G};CALL [{R64}+{IMM8}];{L}:;",
    "JNP {L};JMP {L}; {G};CALL [{R64}+{IMM8}];{L}:;",
    "JNS {L};JMP {L}; {G};CALL [{R64}+{IMM8}];{L}:;",
    "JNE {L};JMP {L}; {G};CALL [{R64}+{IMM16}];{L}:;",
    "JNE {L};JMP {L}; {G};CALL [{R64}+{IMM16}];{L}:;",
    "JNZ {L};JMP {L}; {G};CALL [{R64}+{IMM16}];{L}:;",
    "JA {L};JMP {L}; {G};CALL [{R64}+{IMM16}];{L}:;",
    "JAE {L};JMP {L}; {G};CALL [{R64}+{IMM16}];{L}:;",
    "JGE {L};JMP {L}; {G};CALL [{R64}+{IMM16}];{L}:;",
    "JLE {L};JMP {L}; {G};CALL [{R64}+{IMM16}];{L}:;",
    "JNP {L};JMP {L}; {G};CALL [{R64}+{IMM16}];{L}:;",
    "JNS {L};JMP {L}; {G};CALL [{R64}+{IMM16}];{L}:;",
    "JNE {L};JMP {L}; {G};CALL [{R64}+{IMM32}];{L}:;",
    "JNZ {L};JMP {L}; {G};CALL [{R64}+{IMM32}];{L}:;",
    "JA {L};JMP {L}; {G};CALL [{R64}+{IMM32}];{L}:;",
    "JAE {L};JMP {L}; {G};CALL [{R64}+{IMM32}];{L}:;",
    "JGE {L};JMP {L}; {G};CALL [{R64}+{IMM32}];{L}:;",
    "JLE {L};JMP {L}; {G};CALL [{R64}+{IMM32}];{L}:;",
    "JNP {L};JMP {L}; {G};CALL [{R64}+{IMM32}];{L}:;",
    "JNS {L};JMP {L}; {G};CALL [{R64}+{IMM32}];{L}:;",
    "JNE {L};JMP {L}; {G};CALL [{R64}+{IMM64}];{L}:;",
    "JNZ {L};JMP {L}; {G};CALL [{R64}+{IMM64}];{L}:;",
    "JA {L};JMP {L}; {G};CALL [{R64}+{IMM64}];{L}:;",
    "JAE {L};JMP {L}; {G};CALL [{R64}+{IMM64}];{L}:;",
    "JGE {L};JMP {L}; {G};CALL [{R64}+{IMM64}];{L}:;",
    "JLE {L};JMP {L}; {G};CALL [{R64}+{IMM64}];{L}:;",
    "JNP {L};JMP {L}; {G};CALL [{R64}+{IMM64}];{L}:;",
    "JNS {L};JMP {L}; {G};CALL [{R64}+{IMM64}];{L}:;",
]

x64_REGISTER_MATH = [
    "MOV {R64}, {IMM8};",
    "MOV {R64}, [rsp+{IMM8}];",
    "XOR {R64}, {IMM8};",
    "XOR {R64}, [rsp+{IMM8}];",
    "DEC {R64};",
    "NEG {R64};",
    "NOT {R64};",
    "INC {R64};",
    "BSWAP {R64};",
    "ROL {R64},{IMM8};",
    "ROR {R64},{IMM8};",
    "ADD {R64}, {IMM8};",
    "ADD {R64}, [rsp+{IMM8}];",
    "SUB {R64}, {IMM8};"
    "SUB {R64}, [rsp+{IMM8}];",
    "AND {R64}, {IMM8};",
    "AND {R64}, [rsp+{IMM8}];",
    "OR {R64}, {IMM8};",
    "OR {R64}, [rsp+{IMM8}];",
    "LEA {R64}, [rsp+{IMM8}];",
    "IMUL {R64}, [rsp-{IMM8}];",
    "IMUL {R64}, [rsp-{IMM8}], {IMM32};",
    "MOV {R64}, {IMM16};",
    "MOV {R64}, {IMM32};",
    "MOV {R64}, {IMM64};",
    "XOR {R64}, {IMM16};",
    "XOR {R64}, {IMM32};"
]

GARBAGE_ASM = [
    "NOT {R64};{G};NOT {R64};",
    "NEG {R64};{G};NEG {R64};",
    "INC {R64};{G};DEC {R64};",
    "DEC {R64};{G};INC {R64};",
    "PUSH {R64};{G};POP {R64};",
    "BSWAP {R64};{G};BSWAP {R64};",
    "ADD {R64},{IMM8};{G};SUB {R64},{IMM8};",
    "SUB {R64},{IMM8};{G};ADD {R64},{IMM8};",
    "ADD {R64},{IMM16};{G};SUB {R64},{IMM16};",
    "SUB {R64},{IMM16};{G};ADD {R64},{IMM16};",
    "ADD {R64},{IMM32};{G};SUB {R64},{IMM32};",
    "SUB {R64},{IMM32};{G};ADD {R64},{IMM32};",
    "ROR {R64},{IMM8};{G};ROL {R64},{IMM8};",
    "ROL {R64},{IMM8};{G};ROR {R64},{IMM8};"
]
