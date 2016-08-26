OPT=-Os -s -Wall
LDFLAGS=-nostartfiles -lntdll -nostdlib -luser32 -lcryptsp -lADVAPI32 -lshlwapi -lkernel32 -lole32 -Wl,--exclude-all-symbols -Wl,--enable-stdcall-fixup
CFLAGS=-fno-ident -fno-stack-check -fno-stack-protector -mno-stack-arg-probe -fno-asynchronous-unwind-tables -fno-exceptions -fno-align-functions -fno-align-labels -fno-align-jumps -funsigned-char -mtune=core2
all: slshim32.dll slshim64.dll
slshim32.dll: slshim.c
	gcc -m32 -L/mingw32/i686-w64-mingw32/lib -Wl,-e_dll_main -municode $(OPT) $< slshim.def -shared -o $@ $(CFLAGS) $(LDFLAGS)
slshim64.dll: slshim.c
	gcc -Wl,-edll_main -municode $(OPT) $< slshim.def -shared -o $@ $(CFLAGS) $(LDFLAGS)

clean:
	rm -f *.dll
