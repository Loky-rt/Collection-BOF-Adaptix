CC64 = x86_64-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
CFLAGS = -I src -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -DBOF -s -c

all: bof

bof: clean
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	@($(CC64) $(CFLAGS) src/reg_bof.c -o _bin/reg.x64.o && $(STRIP64) _bin/reg.x64.o) && echo '[+] reg (x64)' || echo '[!] reg (x64)'

clean:
	@(rm -rf _bin)
