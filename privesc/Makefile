CC64    = x86_64-w64-mingw32-gcc
CC86    = i686-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
STRIP86 = i686-w64-mingw32-strip --strip-unneeded
CFLAGS  = -I _include -w -Os -DBOF -s -c

all: bof

bof: clean
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	@($(CC64) $(CFLAGS) src/privesc_bof.c -o _bin/privesc.x64.o && $(STRIP64) _bin/privesc.x64.o) && echo '[+] privesc x64' || echo '[!] privesc x64'
	@($(CC86) $(CFLAGS) src/privesc_bof.c -o _bin/privesc.x86.o && $(STRIP86) _bin/privesc.x86.o) && echo '[+] privesc x86' || echo '[!] privesc x86'

clean:
	@(rm -rf _bin)

.PHONY: all bof clean
