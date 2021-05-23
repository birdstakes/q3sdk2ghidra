import glob
import os
import shutil
import subprocess
from pathlib import Path
from pycparser import c_ast, c_generator, c_parser


def main():
    try:
        path = Path(__file__).parent.resolve()
        os.system(f'subst Q: {path}')
        os.environ['PATH'] = 'Q:/quake3/bin_nt;' + os.environ['PATH']
        os.chdir('Q:')

        #fix_source()
        #build_vms()
        #translate_vms()
        process_headers()
        #ghidra()
    finally:
        os.system('subst Q: /D')


def fix_source():
    for path in ('quake3/code/game/g_local.h', 'quake3/code/game/g_syscalls.c'):
        path = Path(path)
        backup_path = path.with_suffix('.bak')
        if backup_path.exists():
            continue
        path.rename(backup_path)
        with open(backup_path, 'r') as src, open(path, 'w') as dst:
            # fix trap_Trace signature
            dst.write(src.read().replace(
                'const vec3_t mins, const vec3_t maxs, const vec3_t end',
                'vec3_t mins, vec3_t maxs, const vec3_t end',
            ))


def build_vms():
    os.system('cd quake3/code/game & game.bat')
    os.system('cd quake3/code/cgame & cgame.bat')
    os.system('cd quake3/code/q3_ui & q3_ui.bat')
    Path('quake3/baseq3/vm/q3_ui.qvm').replace('quake3/baseq3/vm/ui.qvm')
    Path('quake3/baseq3/vm/q3_ui.map').replace('quake3/baseq3/vm/ui.map')


def translate_vms():
    for vm in ('qagame', 'cgame', 'ui'):
        base = Path('quake3/baseq3/vm').joinpath(vm)
        qvm = base.with_suffix('.qvm')
        symbols = base.with_suffix('.map')
        print(f'translating {qvm}')
        os.system(f'python qvm-translator/translate.py {qvm} {symbols}')


def ghidra():
    process_headers()

    # work around scriptPath not working for python scripts in 9.2
    os.chdir('ghidra')

    analyze = Path('C:/Users/Josh/Programs/ghidra/support/analyzeHeadless.bat')
    subprocess.run([
        analyze,
        '.', 'baseq3',
        '-postScript', 'parse_headers.py',
        '-overwrite',
        '-import', '../quake3/baseq3/vm/qagame.xml'
    ])


    '''
    analyze = Path('C:/Users/Josh/Programs/ghidra/support/analyzeHeadless.bat')
    subprocess.run([
        analyze,
        '.', 'baseq3',
        '-postScript', 'parse_headers.py',
        '-noanalysis',
        '-process', 'qagame',
    ])
    '''

game_source_files = [
    'g_main.c',
    'g_syscalls.c',
    'bg_misc.c',
    'bg_lib.c',
    'bg_pmove.c',
    'bg_slidemove.c',
    'q_math.c',
    'q_shared.c',
    'ai_dmnet.c',
    'ai_dmq3.c',
    'ai_main.c',
    'ai_chat.c',
    'ai_cmd.c',
    'ai_team.c',
    'g_active.c',
    'g_arenas.c',
    'g_bot.c',
    'g_client.c',
    'g_cmds.c',
    'g_combat.c',
    'g_items.c',
    'g_mem.c',
    'g_misc.c',
    'g_missile.c',
    'g_mover.c',
    'g_session.c',
    'g_spawn.c',
    'g_svcmds.c',
    'g_target.c',
    'g_team.c',
    'g_trigger.c',
    'g_utils.c',
    'g_weapon.c',
    'ai_vcmd.c',
]

cgame_source_files = [
    '../game/bg_misc.c',
    '../game/bg_pmove.c',
    '../game/bg_slidemove.c',
    '../game/bg_lib.c',
    '../game/q_math.c',
    '../game/q_shared.c',
    'cg_consolecmds.c',
    'cg_draw.c',
    'cg_drawtools.c',
    'cg_effects.c',
    'cg_ents.c',
    'cg_event.c',
    'cg_info.c',
    'cg_localents.c',
    'cg_main.c',
    'cg_marks.c',
    'cg_players.c',
    'cg_playerstate.c',
    'cg_predict.c',
    'cg_scoreboard.c',
    'cg_servercmds.c',
    'cg_snapshot.c',
    'cg_view.c',
    'cg_weapons.c',
]

class EnumEvaluator(c_ast.NodeVisitor):
    def __init__(self):
        super().__init__()
        self.enums = {}
        self.evaluator = ExpressionEvaluator()

    def visit_Enum(self, node):
        current = 0
        for enumerator in node.values.enumerators:
            name = enumerator.name
            if enumerator.value is None:
                value = current
            else:
                value = self.evaluator.visit(enumerator.value)
            current += 1
            assert name not in self.enums
            self.enums[name] = value

class ExpressionEvaluator:
    def __init__(self, enums=None):
        self.enums = enums or {}

    def visit(self, node):
        method = 'visit_' + node.__class__.__name__
        return getattr(self, method, self.generic_visit)(node)

    def generic_visit(self, node):
        raise Exception(f'node {node.__class__.__name__} not implemented')

    def visit_BinaryOp(self, node):
        left = self.visit(node.left)
        right = self.visit(node.right)
        if node.op == '+':
            return left + right
        elif node.op == '-':
            return left - right
        elif node.op == '*':
            return left * right
        elif node.op == '<<':
            return left << right
        else:
            raise Exception(f'binary op {node.op} not implemented')

    def visit_Constant(self, node):
        assert node.type == 'int'
        return int(node.value, 0)

    def visit_ID(self, node):
        return self.enums[node.name]

class ArraySizeFixer(c_ast.NodeVisitor):
    def __init__(self, enums=None):
        super().__init__()
        self.evaluator = ExpressionEvaluator(enums)

    def visit_Decl(self, node):
        if not isinstance(node.type, c_ast.ArrayDecl):
            return
        if 'extern' in node.storage:
            return

        if not isinstance(node.type.dim, c_ast.Constant):
            if node.type.dim is None:
                dim = len(node.init.exprs)
            else:
                dim = self.evaluator.visit(node.type.dim)
            node.type.dim = c_ast.Constant(type='int', value=str(dim))

def process_headers():
    def cpp(src, dst):
        subprocess.run([
            'quake3/source/lcc/bin/cpp',
            '-Iquake3/code/game', '-Iquake3/code/cgame', '-Iquake3/code/q3_ui',
            '-DQ3_VM', '-DID_INLINE=',
            src, dst
        ])

    #cpp('quake3/code/game/g_local.h', 'ghidra/g_local.h')

    # maybe ghidra doesn't need the c files, just the result of finding their types
    # though some types are defined in c files... maybe extract them?

    parser = c_parser.CParser()
    generator = c_generator.CGenerator()
    for path in game_source_files:
        print(path)
        print('='*80)

        path = Path('quake3/code/game/').joinpath(path)
        cpp(path, 'ghidra/temp.c')

        with open('ghidra/temp.c') as f:
            ast = parser.parse(f.read(), f.name)

        enum_evaluator = EnumEvaluator()
        enum_evaluator.visit(ast)
        array_size_fixer = ArraySizeFixer(enum_evaluator.enums)
        array_size_fixer.visit(ast)

        for decl in ast.ext:
            if not isinstance(decl, c_ast.Decl):
                continue
            if isinstance(decl.type, c_ast.FuncDecl):
                continue
            if decl.name is None:
                continue
            if 'static' in decl.storage or 'extern' in decl.storage:
                continue

            # TODO
            # spit out only decls into a giant header for ghidra?

            print(f'{decl.name} ::  {generator.visit(decl.type)}')

        print()


if __name__ == '__main__':
    main()
