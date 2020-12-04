import pefile
from helpers import *
from mlog import *

class MPE:
    def __init__(self, infile):
        self.pe = pefile.PE(infile)
        self.pe_bytes = read_bytes(infile)
        self.imports = []
        self.shellcode_bytes = None

    def get_address_of_entry_point(self):
        return self.pe.OPTIONAL_HEADER.AddressOfEntryPoint

    def locate_section_from_rva(self, rva):
        for section in self.pe.sections:
            if section.contains_rva(rva):
                return section

    def load_shellcode(self, infile):
        self.shellcode_bytes = read_bytes(infile)

    def vir_to_raw(self, rva):
        sect = self.locate_section_from_rva(rva)
        if sect is not None:
            return rva - sect.VirtualAddress + sect.PointerToRawData
        else:
            return None

    @staticmethod
    def is_exec_section(section):
        if section.Characteristics & 0x40000000 and section.Characteristics & 0x20000000:
            return True

    def get_imports(self):
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            for func in entry.imports:
                self.imports.append(func.address-self.pe.OPTIONAL_HEADER.ImageBase)

    def write_to_addr(self, rva, data):
        section = self.locate_section_from_rva(rva)
        logging.log(INFO, "The selected RVA is located in {0} section".format(section.Name.decode('utf-8')))
        if MPE.is_exec_section(section):
            logging.log(SUCCESS, "The {0} section is executable".format(section.Name.decode('utf-8')))
        else:
            logging.log(ERROR, "The {0} section is not executable".format(section.Name.decode('utf-8')))
            logging.log(ERROR, "Exiting...")
            sys.exit(0)
        raw_addr = self.vir_to_raw(rva)
        logging.log(INFO, "Attempting to write {0} bytes to VirtAddr: {1} RawAddr: {2}".format(len(data), hex(rva), hex(raw_addr)))
        for i in range(0, len(data)):
            self.pe_bytes[raw_addr + i] = data[i]

        sec_end_offset = section.PointerToRawData + section.SizeOfRawData
        sec_slack = 0x256
        sec_end_offset = sec_end_offset - sec_slack
        if raw_addr + len(data) > sec_end_offset:
            logging.log(ERROR, "Length of the payload exceeded the .text section by {0} bytes".format(hex(raw_addr + len(data) - sec_end_offset)))
            sys.exit(0)
        else:
            logging.log(SUCCESS, "Wrote {0} bytes to {1}".format(len(data), hex(raw_addr)))
            logging.log(INFO, "The injected code boundaries: Start: {0} End: {1}".format(hex(raw_addr), hex(raw_addr + len(data))))