from __main__ import *

from ghidra.program.model.listing import CodeUnit
from collections import namedtuple

StackString = namedtuple("StackString", ["addr", "s"])

def add_bookmark_comment(stack_string):
    cu = getCurrentProgram().getListing().getCodeUnitAt(stack_string.addr)
    createBookmark(stack_string.addr, "stack string", stack_string.s)
    cu.setComment(CodeUnit.EOL_COMMENT, "stack string: " + stack_string.s)

def is_mov(unit):
    name = unit.getMnemonicString()
    op_num = unit.getNumOperands()
    return name == "MOV" and op_num == 2

def is_mov_char_to_stack(unit):
    if not is_mov(unit):
        return False
    refs = unit.getOperandReferences(0)
    if len(refs) == 0 or not refs[0].getReferenceType().isWrite():
        return False
    scalar = unit.getScalar(1)
    if scalar is None or not is_ascii(scalar.getValue()):
        return False
    return True

def find_stack_string(code_units):
    rslt = []
    idx = 0
    while idx < len(code_units):
        s = ""
        if not is_mov_char_to_stack(code_units[idx]):
            idx += 1
            continue
        ctr = 0
        addr = code_units[idx].getOperandReferences(0)[0].getFromAddress()
        while is_mov_char_to_stack(code_units[idx + ctr]) and idx + ctr < len(code_units):
            scalar = code_units[ctr + idx].getScalar(1).getValue()
            if is_ascii(scalar):
                s += chr(scalar)
            ctr += 1
        idx += ctr
        if ctr > 1:
            stack_string = StackString(addr, s)
            add_bookmark_comment(stack_string)

def is_ascii(val):
    return 0x20 <= val <= 0x7E or val in ['\x09', '\x0a']

def main():
    current_program = getCurrentProgram()
    listing = current_program.getListing()

    pattern = "\\xc6\\x45.{1,2}["
    for i in range(32, 128):
        pattern += "\\x%02x" % i
    pattern += "]"

    functions = []
    for addr in findBytes(None, pattern, -1):
        func = getFunctionContaining(addr)
        if func not in functions:
            functions.append(func)
            code_units = listing.getCodeUnits(func.getEntryPoint(), True)
            find_stack_string(list(code_units))

if __name__ == "__main__":
    main()
