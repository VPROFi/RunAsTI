env = Environment(
    CPPPATH = Dir('.'),
    CPPFLAGS = ['/D_UNICODE', '/DUNICODE', '/D_CONSOLE', '/EHsc'],
    LINKFLAGS = ['/subsystem:console', '/pdbaltpath:%_PDB%', '/ignore:4099']
)

SConsignFile('build/.sconsign.dblite')
#env['LINKFLAGS'] = env['LINKFLAGS'] + '/subsystem:console /pdbaltpath:%_PDB%'

base_path = 'build/'+('debug/' if ARGUMENTS.get('debug', 0) else 'release/')+env['TARGET_ARCH']+'/'

res = SConscript('res/SConscript',
           variant_dir = base_path + 'res',
           duplicate = 0,
           exports = 'env')

program = SConscript('src/SConscript',
           variant_dir = base_path + 'bin',
           duplicate = 0,
           exports = 'env res')

Depends(program, res)