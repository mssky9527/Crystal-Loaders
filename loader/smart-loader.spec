x86:
    generate $KEY 2048

    load "bin/loader.x86.o"
        make pic +gofirst +optimize

        fixptrs "_caller"
    
        dfr "_smart_resolve" "strings"

        patch "_pGetModuleHandle" $GMH
	    patch "_pGetProcAddress"  $GPA
    
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
    
        dfr "smart_resolve" "strings"

        patch "pGetModuleHandle" $GMH
	    patch "pGetProcAddress"  $GPA

        mergelib "../libtcg.x64.zip"

        push $DLL
            xor $KEY
            preplen
            link "dll_data"

        push $KEY
            preplen
            link "key_data"
    
        export
