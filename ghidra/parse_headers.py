from ghidra.app.util.cparser.C import CParser
from ghidra.app.cmd.function import ApplyFunctionDataTypesCmd
from ghidra.program.model.symbol import SourceType

paths = [
    'g_local.h'
]

dtMgr = currentProgram.getDataTypeManager()
parser = CParser(dtMgr, True, None)

for path in paths:
    with open(path) as f:
        parser.parse(f.read())

cmd = ApplyFunctionDataTypesCmd([dtMgr], None, SourceType.USER_DEFINED, True, True)
cmd.applyTo(currentProgram)

# TODO
# set types for data items
# set return value location to EAX for functions that return floats
