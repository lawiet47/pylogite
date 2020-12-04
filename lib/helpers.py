# Helpers
import sys
from mlog import *
import colorama
from colorama import *

def print_banner():
    colorama.init()
    banner = """
    ###### ##  ## ##     #!#### #!###  ## ####!# ###!##
    ##  !! ##  ## ##     ##  ## ##     ##   ##   ##
    ##*### #!#### ##     ##  !# ##     !#   ##   #!####
    #!       #!   ##     ##  ## ##  ## ##   #!   !#
    ##       ##   #!#### ##!### ###!## ##   ##   ####!#\n"""
    banner = banner.replace('#', '\033[43m\033[33m \033[0m').replace('!', '\033[47m\033[37m \033[0m').replace('*', '\033[43m\033[33m \033[0m')
    print(banner)


def read_bytes(infile):
    data = []
    try:
        with open(infile, 'rb') as f:
            data = bytearray(f.read())
    except:
        logging.log(ERROR, "Error accessing {0}".format(infile))
        sys.exit(0)
    return data


def write_bytes(outfile, data):
    try:
        with open(outfile, 'wb') as f:
            f.write(data)
    except:
        logging.log(ERROR, "Error accessing {0}".format(outfile))
        sys.exit(0)
    return len(data)


def to_integer(opstr):
    try:
        digit = int(opstr, 16)
        return digit
    except:
        return None


def insert_bytes(rbytes, index, ibytes):
    if len(rbytes) <= 0:
        logging.log(ERROR, "Got buffer with 0 size in insert_bytes")
        sys.exit(0)
    if len(ibytes) == 0:
        return rbytes
    rbytes[index:index] = ibytes
    return rbytes


def replace_bytes(rbytes, index, length, ibytes):
    if len(rbytes) <= 0:
        logging.log(ERROR, "Got buffer with 0 size in replace_bytes")
        sys.exit(0)
    if length <= 0:
        return rbytes
    if len(ibytes) <= 0:
        return rbytes
    for i in range(0, length):
        rbytes[index+i] = ibytes[i]
    return rbytes
