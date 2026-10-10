CC64    = x86_64-w64-mingw32-gcc
CC86    = i686-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
STRIP86 = i686-w64-mingw32-strip --strip-unneeded
CFLAGS  = -I _include -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -DBOF -s -c

all: bof

bof: clean
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	# 64-bit
	@($(CC64) $(CFLAGS) src/fw_list.c   -o _bin/fw_list.x64.o   && $(STRIP64) _bin/fw_list.x64.o)   && echo '[+] fw_list x64'   || echo '[!] fw_list x64'
	@($(CC64) $(CFLAGS) src/fw_add.c    -o _bin/fw_add.x64.o    && $(STRIP64) _bin/fw_add.x64.o)    && echo '[+] fw_add x64'    || echo '[!] fw_add x64'
	@($(CC64) $(CFLAGS) src/fw_delete.c -o _bin/fw_delete.x64.o && $(STRIP64) _bin/fw_delete.x64.o) && echo '[+] fw_delete x64' || echo '[!] fw_delete x64'
	@($(CC64) $(CFLAGS) src/fw_find.c   -o _bin/fw_find.x64.o   && $(STRIP64) _bin/fw_find.x64.o)   && echo '[+] fw_find x64'   || echo '[!] fw_find x64'
	@($(CC64) $(CFLAGS) src/fw_toggle.c -o _bin/fw_toggle.x64.o && $(STRIP64) _bin/fw_toggle.x64.o) && echo '[+] fw_toggle x64' || echo '[!] fw_toggle x64'
	# 32-bit
	@($(CC86) $(CFLAGS) src/fw_list.c   -o _bin/fw_list.x86.o   && $(STRIP86) _bin/fw_list.x86.o)   && echo '[+] fw_list x86'   || echo '[!] fw_list x86'
	@($(CC86) $(CFLAGS) src/fw_add.c    -o _bin/fw_add.x86.o    && $(STRIP86) _bin/fw_add.x86.o)    && echo '[+] fw_add x86'    || echo '[!] fw_add x86'
	@($(CC86) $(CFLAGS) src/fw_delete.c -o _bin/fw_delete.x86.o && $(STRIP86) _bin/fw_delete.x86.o) && echo '[+] fw_delete x86' || echo '[!] fw_delete x86'
	@($(CC86) $(CFLAGS) src/fw_find.c   -o _bin/fw_find.x86.o   && $(STRIP86) _bin/fw_find.x86.o)   && echo '[+] fw_find x86'   || echo '[!] fw_find x86'
	@($(CC86) $(CFLAGS) src/fw_toggle.c -o _bin/fw_toggle.x86.o && $(STRIP86) _bin/fw_toggle.x86.o) && echo '[+] fw_toggle x86' || echo '[!] fw_toggle x86'

clean:
	@(rm -rf _bin)

.PHONY: all bof clean
