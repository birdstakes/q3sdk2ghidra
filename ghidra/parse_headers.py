from ghidra.app.cmd.data import CreateDataCmd
from ghidra.app.util.cparser.C import CParser
from ghidra.app.cmd.function import ApplyFunctionDataTypesCmd
from ghidra.program.model.data import DoubleDataType, FloatDataType
from ghidra.program.model.listing import VariableStorage
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

vec3_t = dtParser.parse("vec3_t")

f = getFirstFunction()
while f is not None:
    f.setCallingConvention("__cdecl")

    for param in f.getParameters():
        if param.getDataType().isEquivalent(DoubleDataType.dataType):
            print('fixing %s double param' % f)
            param.setDataType(FloatDataType.dataType, SourceType.ANALYSIS)
        elif param.getDataType().isEquivalent(vec3_t):
            # TODO other vec_* types
            print('fixing %s vec3_t param' % f)
            param.setDataType(dtMgr.getPointer(FloatDataType.dataType), SourceType.ANALYSIS)

    is_float_return = f.getReturn().getDataType().isEquivalent(FloatDataType.dataType)
    is_double_return = f.getReturn().getDataType().isEquivalent(DoubleDataType.dataType)

    if is_float_return or is_double_return:
        print('fixing %s return' % f)
        f.setCustomVariableStorage(True)
        f.setReturn(
            FloatDataType.dataType,
            VariableStorage(currentProgram, [currentProgram.getRegister('eax')]),
            SourceType.ANALYSIS
        )

    f = getFunctionAfter(f)

# TODO
# preprocess a file with all the defines in it and use populateDefineEquates
#  might need to put them in separate files with the original names
