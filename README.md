# PyloGite - Metamorphic Code Generator &amp; Loader


![](png/pylogite.PNG)

# What is it?

Pylogite is a metamorphic code generator. The tool's aim is to take a Position independent shellcode obfuscate it by changing/deleting/adding x86 instructions and inject it into the given benign PE file. Every generated sample will be different from the last one.

![](png/pylogite.gif)

# What can it do?

| Feature  | :heavy_check_mark: / TODO |
| ------------- | ------------- |
| Insert garbage instructions  | :heavy_check_mark: |
| Obfuscate relative branch instructions  | :heavy_check_mark:  |
| Graph view destruction | :heavy_check_mark: |
| Obfuscate mov instructions  | :heavy_check_mark:  |
| Unsafe registry arithmetics | :heavy_check_mark: |
| Obfuscate push/pop instructions | :heavy_check_mark: |
| Obfuscate cmp instructions | TODO |
| Add SSE instructions | TODO |
| Control Flow Deception | TODO |

# How?

The program takes a Position independent shellcode (code section must not have any offsets to .data/.rdata sections) and obfuscates it by changing already existing instructions with new x86 instructions which perform the same action but are different in size. Program can also insert garbage instructions consisting of branches, calls, unsafe registry arithmetics anywhere in the code Hopefully achieving metamorphism.

Currently static immediate values that are being moved with `mov` instructions are obfuscated to hide signature values. Later on immediate values that are being used in `cmp`, `push`, `add` and `sub` instructions will also be obfuscated.

Below are two different outputs of the same shellcode:

![](png/pylogite_diff.PNG)

Below is the section info for the original Microsoft Signed `cmd.exe` and the modified version of it.

### Original:

| Name | RVA | Size | Permissions | Entropy |
| ------------- | ------------- | ------------- | ------------- | ------------- |
| .text | 0x1000 | 0x2f000 | READ_EXECUTE | 6.37579802 |
| .rdata | 0x30000 | 0xb000 | READ_ONLY | 4.89710901 |
| .data | 0x3b000 | 0x1c000 | READ_WRITE | 3.24267717 |
| .pdata | 0x57000 | 0x3000 | READ_ONLY | 5.42258726 |
| .didat | 0x5a000 | 0x1000 | READ_WRITE | 1.02781326 |
| .rsrc | 0x5b000 | 0x9000 | READ_ONLY | 4.35942953 |
| .reloc | 0x64000 | 0x1000 | READ_ONLY | 4.58648411 |

### Modified:

| Name | RVA | Size | Permissions | Entropy |
| ------------- | ------------- | ------------- | ------------- | ------------- |
| .text | 0x1000 | 0x2f000 | READ_EXECUTE | 6.38199005 |
| .rdata | 0x30000 | 0xb000 | READ_ONLY | 4.89710901 |
| .data | 0x3b000 | 0x1c000 | READ_WRITE | 3.24267717 |
| .pdata | 0x57000 | 0x3000 | READ_ONLY | 5.42258726 |
| .didat | 0x5a000 | 0x1000 | READ_WRITE | 1.02781326 |
| .rsrc | 0x5b000 | 0x9000 | READ_ONLY | 4.35942953 |
| .reloc | 0x64000 | 0x1000 | READ_ONLY | 4.58648411 |
