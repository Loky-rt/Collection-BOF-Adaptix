CC64 = x86_64-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
CFLAGS = -masm=intel -Wall -Wno-pointer-sign -c -I../../include -DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0601

all: bof

bof: clean
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	@($(CC64) $(CFLAGS) src/zip.c -o _bin/zip.x64.o && $(STRIP64) _bin/zip.x64.o) && echo '[+] zip (x64)' || echo '[!] reg (x64)'
clean:
	@(rm -rf _bin)

