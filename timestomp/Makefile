CC64 = x86_64-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
CFLAGS = -I ./_include -w -Wno-incompatible-pointer-types -Os -s -DBOF -c

all: bof

bof:
	@(mkdir -p _bin 2>/dev/null) && echo 'creating _bin' || echo '_bin exists'
	@($(CC64) $(CFLAGS) src/timestomp.c -o _bin/timestomp.x64.o && $(STRIP64) _bin/timestomp.x64.o) && echo '[+] timestomp' || echo '[!] timestomp'
clean:
	@(rm -rf _bin)
