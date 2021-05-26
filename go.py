import glob
import io
import os
import shutil
import subprocess
from pathlib import Path
from pcpp.preprocessor import Preprocessor
from pycparser import c_ast, c_generator, c_parser


def main():
    try:
        path = Path(__file__).parent.resolve()
        os.system(f'subst Q: {path}')
        os.environ['PATH'] = 'Q:/quake3/bin_nt;' + os.environ['PATH']
        os.chdir('Q:')

        fix_source()
        build_vms()
        translate_vms()
        ghidra()
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
    def run(vm):
        # work around scriptPath not working for python scripts in 9.2
        os.chdir('ghidra')

        analyze = Path('C:/Users/Josh/Programs/ghidra/support/analyzeHeadless.bat')

        if True:
            subprocess.run([
                analyze,
                '.', 'baseq3',
                '-postScript', 'parse_headers.py',
                '-overwrite',
                '-import', f'../quake3/baseq3/vm/{vm}.xml'
            ])
        else:
            analyze = Path('C:/Users/Josh/Programs/ghidra/support/analyzeHeadless.bat')
            subprocess.run([
                analyze,
                '.', 'baseq3',
                '-postScript', 'parse_headers.py',
                '-noanalysis',
                '-process', vm,
            ])

        os.chdir('..')

    process_source_files(game_source_files)
    run('qagame')

    process_source_files(cgame_source_files)
    run('cgame')

    #process_source_files(ui_source_files)
    #run('ui')

game_source_files = [
    Path('quake3/code/game/').joinpath(path) for path in [
        'g_main.c',
        #'g_syscalls.c',
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
]

cgame_source_files = [
    Path('quake3/code/cgame/').joinpath(path) for path in [
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
]

ui_source_files = [
    Path('quake3/code/q3_ui/').joinpath(path) for path in [
        'ui_main.c',
        'ui_cdkey.c',
        'ui_ingame.c',
        'ui_serverinfo.c',
        'ui_confirm.c',
        'ui_setup.c',
        '../game/bg_misc.c',
        '../game/bg_lib.c',
        '../game/q_math.c',
        '../game/q_shared.c',
        'ui_gameinfo.c',
        'ui_atoms.c',
        'ui_connect.c',
        'ui_controls2.c',
        'ui_demo2.c',
        'ui_mfield.c',
        'ui_credits.c',
        'ui_menu.c',
        'ui_options.c',
        'ui_display.c',
        'ui_sound.c',
        'ui_network.c',
        'ui_playermodel.c',
        'ui_players.c',
        'ui_playersettings.c',
        'ui_preferences.c',
        'ui_qmenu.c',
        'ui_servers2.c',
        'ui_sparena.c',
        'ui_specifyleague.c',
        'ui_specifyserver.c',
        'ui_splevel.c',
        'ui_sppostgame.c',
        'ui_startserver.c',
        'ui_syscalls.c',
        'ui_team.c',
        'ui_video.c',
        'ui_cinematics.c',
        'ui_spskill.c',
        'ui_addbots.c',
        'ui_removebots.c',
        'ui_teamorders.c',
        'ui_mods.c',
    ]
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

class ArraySizeSimplifier(c_ast.NodeVisitor):
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
                if isinstance(node.init, c_ast.InitList):
                    dim = len(node.init.exprs)
                elif isinstance(node.init, c_ast.Constant) and node.init.type == 'string':
                    dim = len(node.init.value) - 2 + 1 # stip off quotes and add null byte
                else:
                    print('warning: unhandled array size')
                    dim = 0
            else:
                dim = self.evaluator.visit(node.type.dim)
            node.type.dim = c_ast.Constant(type='int', value=str(dim))

class CPP(Preprocessor):
    def __init__(self):
        super().__init__()
        self.expression_evaluator = ExpressionEvaluator()
        self.c_parser = c_parser.CParser()
        self.define('Q3_VM')
        self.define('ID_INLINE')
        self.add_path('quake3/code/game')
        self.add_path('quake3/code/cgame')
        self.add_path('quake3/code/q3_ui')

    def process(self, path):
        with open(path) as f:
            self.parse(f.read(), path)
        buf = io.StringIO()
        self.write(buf)
        return buf.getvalue()

    def eval(self, expression):
        # hackiest shit on earth nominee
        buf = io.StringIO()
        self.parse(expression)
        self.write(buf)
        try:
            ast = self.c_parser.parse(f'int x = {buf.getvalue()};')
            return self.expression_evaluator.visit(ast.ext[0].init)
        except:
            raise ValueError('invalid integral expression') from None

def process_source_files(files):
    parser = c_parser.CParser()
    generator = c_generator.CGenerator()
    result = io.StringIO()
    types = io.StringIO()

    handled_functions = set()
    defines = {}

    for path in files:
        print(f'processing {path}...')

        cpp = CPP()
        ast = parser.parse(cpp.process(path))

        for define in cpp.macros:
            try:
                defines[define] = (cpp.eval(define), cpp.macros[define].source)
            except ValueError:
                pass

        enum_evaluator = EnumEvaluator()
        enum_evaluator.visit(ast)
        array_size_simplifier = ArraySizeSimplifier(enum_evaluator.enums)
        array_size_simplifier.visit(ast)

        # TODO convert function pointers to ints
        #  maybe do this in ghidra though so we can easily create references to the
        #  functions afterwards

        for decl in ast.ext:
            if isinstance(decl, c_ast.FuncDef):
                # we don't care about the function's body
                decl = decl.decl

            if hasattr(decl, 'storage') and 'extern' in decl.storage:
                continue

            if (
                isinstance(decl, c_ast.Enum)
                or isinstance(decl, c_ast.FuncDecl) # TODO remove if possible
                or isinstance(decl, c_ast.FuncDef)
                or isinstance(decl, c_ast.Struct)
                or isinstance(decl, c_ast.Typedef)
                or (
                    isinstance(decl, c_ast.Decl)
                    and (
                        isinstance(decl.type, c_ast.Struct)
                        or isinstance(decl.type, c_ast.FuncDecl)
                    )
                )
            ):
                if isinstance(decl, c_ast.FuncDecl):
                    # TODO remove this check and corresponding `or isinstance(...` after
                    # ensuring this never happens
                    print('got a FuncDecl')


                # skip functions we've already handled because there are a few small
                # inconsistencies ghidra doesn't like (e.g. vec_t in some declarations
                # but float in others)
                if isinstance(decl, c_ast.Decl) and isinstance(decl.type, c_ast.FuncDecl):
                    if decl.name in handled_functions:
                        continue
                    handled_functions.add(decl.name)

                result.write(f'#line {decl.coord.line}: "{decl.coord.file}"\n')
                result.write(generator.visit(decl) + ';\n')

            if isinstance(decl, c_ast.Decl):
                if isinstance(decl.type, c_ast.FuncDecl):
                    continue
                if decl.name is None:
                    continue

                types.write(f'{decl.name}:{generator.visit(decl.type)}\n')

    with open('ghidra/headers.h', 'w') as f:
        result.seek(0)
        f.write(result.read())
        for name in defines:
            value, source = defines[name]
            if len(source) == 0:
                continue
            source = Path(source).name
            f.write(f'#line 1: "{source}"\n')
            f.write(f'enum define_{name} {{ {name} = {value} }};\n')

    with open('ghidra/types', 'w') as f:
        types.seek(0)
        f.write(types.read())

if __name__ == '__main__':
    main()
