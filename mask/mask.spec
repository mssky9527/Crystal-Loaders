x86:
    load "bin/mask.x86.o"
        make coff +optimize
        mergelib "../libtcg.x86.zip"
        export

x64:
    load "bin/mask.x64.o"
        make coff +optimize
        mergelib "../libtcg.x64.zip"
        export
