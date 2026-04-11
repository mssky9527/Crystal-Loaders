x86:
    generate $KEY 2048

    load "bin/loader.x86.o"
        make pic +gofirst +optimize
    
        fixptrs "_caller"

        dfr "_resolve" "ror13"

        mergelib "../libtcg.x86.zip"

        push $DLL
            xor $KEY
            preplen
            link "dll_data"

        push $KEY
            preplen
            link "key_data"
    
        export

x64:
    generate $KEY 2048
    
    load "bin/loader.x64.o"
        make pic +gofirst +optimize
    
        dfr "resolve" "ror13"
    
        mergelib "../libtcg.x64.zip"

        push $DLL
            xor $KEY
            preplen
            link "dll_data"

        push $KEY
            preplen
            link "key_data"
    
        export
