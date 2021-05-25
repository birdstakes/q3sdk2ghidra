from ghidra.app.cmd.data import CreateDataCmd
from ghidra.app.util.cparser.C import CParser
from ghidra.app.cmd.function import ApplyFunctionDataTypesCmd
from ghidra.program.model.symbol import SourceType
from ghidra.util.data import DataTypeParser

dtMgr = currentProgram.getDataTypeManager()
dtParser = DataTypeParser(dtMgr, None, None, DataTypeParser.AllowedDataTypes.ALL)

parser = CParser(dtMgr, True, None)
with open('game.c') as f:
    parser.parse(f.read())

cmd = ApplyFunctionDataTypesCmd([dtMgr], None, SourceType.USER_DEFINED, True, True)
cmd.applyTo(currentProgram)

with open('types') as f:
    for line in f:
        name, type = line.split(':')

        # TODO remove qualifiers in main script in a non-hacky way
        type = type.replace('const ', '')

        dt = dtParser.parse(type)
        symbols = getSymbols(name, None)
        if len(symbols) != 1:
            print('WARNING: symbol %s does not have one definition' % name)
            continue
        cmd = CreateDataCmd(symbols[0].address, True, dt)
        cmd.applyTo(currentProgram)

# TODO
# set types for data items
# set return value location to EAX for functions that return floats
# preprocess a file with all the defines in it and use populateDefineEquates
#  might need to put them in separate files with the original names
