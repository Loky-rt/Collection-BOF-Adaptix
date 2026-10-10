#include <windows.h>
#include "beacon.h"

WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
WINBASEAPI BOOL   WINAPI KERNEL32$ReadFile(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
WINBASEAPI BOOL   WINAPI KERNEL32$WriteFile(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);
WINBASEAPI BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
WINBASEAPI HANDLE WINAPI KERNEL32$FindFirstFileW(LPCWSTR,LPWIN32_FIND_DATAW);
WINBASEAPI BOOL   WINAPI KERNEL32$FindNextFileW(HANDLE,LPWIN32_FIND_DATAW);
WINBASEAPI BOOL   WINAPI KERNEL32$FindClose(HANDLE);
WINBASEAPI DWORD  WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI BOOL   WINAPI KERNEL32$GetFileSizeEx(HANDLE,PLARGE_INTEGER);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE,DWORD,SIZE_T);
WINBASEAPI BOOL   WINAPI KERNEL32$HeapFree(HANDLE,DWORD,LPVOID);
WINBASEAPI LPVOID WINAPI KERNEL32$HeapReAlloc(HANDLE,DWORD,LPVOID,SIZE_T);
WINBASEAPI int    WINAPI KERNEL32$WideCharToMultiByte(UINT,DWORD,LPCWCH,int,LPSTR,int,LPCCH,LPBOOL);
WINBASEAPI int    WINAPI KERNEL32$MultiByteToWideChar(UINT,DWORD,LPCCH,int,LPWSTR,int);
WINBASEAPI DWORD  WINAPI KERNEL32$SetFilePointer(HANDLE,LONG,PLONG,DWORD);
WINBASEAPI void   WINAPI KERNEL32$RtlMoveMemory(PVOID,CONST VOID*,SIZE_T);
WINBASEAPI void   WINAPI KERNEL32$RtlZeroMemory(PVOID,SIZE_T);
NTSYSAPI  ULONG  NTAPI  NTDLL$RtlComputeCrc32(ULONG,PVOID,ULONG);

#define ZIP_LFH_SIG      0x04034b50UL
#define ZIP_CDH_SIG      0x02014b50UL
#define ZIP_EOCD_SIG     0x06054b50UL
#define ZIP_STORED       0
#define ZIP_VER          20
#define MAX_ENTRIES      8192
#define CHUNK            (512 * 1024)   /* 512KB read chunks */

#pragma pack(push, 1)
typedef struct {
    DWORD sig;
    WORD  verNeeded;
    WORD  flags;
    WORD  method;
    WORD  modTime;
    WORD  modDate;
    DWORD crc32;
    DWORD compSize;
    DWORD uncompSize;
    WORD  nameLen;
    WORD  extraLen;
} LocalFileHeader;

typedef struct {
    DWORD sig;
    WORD  verMadeBy;
    WORD  verNeeded;
    WORD  flags;
    WORD  method;
    WORD  modTime;
    WORD  modDate;
    DWORD crc32;
    DWORD compSize;
    DWORD uncompSize;
    WORD  nameLen;
    WORD  extraLen;
    WORD  commentLen;
    WORD  diskStart;
    WORD  intAttr;
    DWORD extAttr;
    DWORD localOffset;
} CentralDirHeader;

typedef struct {
    DWORD sig;
    WORD  diskNum;
    WORD  startDisk;
    WORD  entriesOnDisk;
    WORD  totalEntries;
    DWORD cdSize;
    DWORD cdOffset;
    WORD  commentLen;
} EndOfCentralDir;
#pragma pack(pop)

typedef struct {
    char  name[MAX_PATH];
    DWORD nameLen;
    DWORD crc32;
    DWORD fileSize;
    DWORD localOffset;
    WORD  dosTime;
    WORD  dosDate;
} ZipEntry;

static HANDLE   g_heap     = NULL;
static HANDLE   g_hZip     = INVALID_HANDLE_VALUE;
static ZipEntry *g_entries = NULL;
static DWORD    g_count    = 0;
static DWORD    g_offset   = 0;   /* current write position in ZIP */

static void ZipWrite(const void *data, DWORD len) {
    DWORD w;
    KERNEL32$WriteFile(g_hZip, data, len, &w, NULL);
    g_offset += w;
}

static int StrLen(const char *s) {
    int n = 0; while (s[n]) n++; return n;
}

static void StrCat(char *dst, const char *src, int maxDst) {
    int dl = StrLen(dst);
    int i  = 0;
    while (src[i] && dl + i + 1 < maxDst) { dst[dl + i] = src[i]; i++; }
    dst[dl + i] = '\0';
}

static void StrCpy(char *dst, const char *src, int maxDst) {
    int i = 0;
    while (src[i] && i + 1 < maxDst) { dst[i] = src[i]; i++; }
    dst[i] = '\0';
}

static WCHAR* ToWide(const char *s) {
    int len = StrLen(s) + 1;
    WCHAR *w = (WCHAR*)KERNEL32$HeapAlloc(g_heap, HEAP_ZERO_MEMORY, len * 2);
    if (w) KERNEL32$MultiByteToWideChar(CP_ACP, 0, s, -1, w, len);
    return w;
}

static BOOL AddFile(const char *zipName, const char *fsPath) {
    if (g_count >= MAX_ENTRIES) {
        BeaconPrintf(CALLBACK_ERROR, "zip: too many entries (max %d)\n", MAX_ENTRIES);
        return FALSE;
    }

    /* Open file */
    WCHAR *wPath = ToWide(fsPath);
    if (!wPath) return FALSE;

    HANDLE hFile = KERNEL32$CreateFileW(wPath, GENERIC_READ,
        FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    KERNEL32$HeapFree(g_heap, 0, wPath);

    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "zip: cannot open %s (err %lu)\n",
            fsPath, KERNEL32$GetLastError());
        return FALSE;
    }

    // Get file size
    LARGE_INTEGER liSize = {0};
    KERNEL32$GetFileSizeEx(hFile, &liSize);
    DWORD fileSize = (DWORD)liSize.QuadPart;

    BYTE *buf = NULL;
    DWORD crc = 0;
    if (fileSize > 0) {
        buf = (BYTE*)KERNEL32$HeapAlloc(g_heap, HEAP_ZERO_MEMORY, fileSize);
        if (!buf) {
            BeaconPrintf(CALLBACK_ERROR, "zip: OOM reading %s (%lu bytes)\n", fsPath, fileSize);
            KERNEL32$CloseHandle(hFile);
            return FALSE;
        }
        DWORD total = 0;
        while (total < fileSize) {
            DWORD toRead = (fileSize - total) > CHUNK ? CHUNK : (fileSize - total);
            DWORD got = 0;
            if (!KERNEL32$ReadFile(hFile, buf + total, toRead, &got, NULL) || got == 0)
                break;
            total += got;
        }
        crc = NTDLL$RtlComputeCrc32(0, buf, total);
        fileSize = total;
    }
    KERNEL32$CloseHandle(hFile);

    // DOS time from file's write time (stored in find data - use 0 if unavailable)
    WORD dosTime = 0, dosDate = 0;


    ZipEntry *e = &g_entries[g_count];
    StrCpy(e->name, zipName, MAX_PATH);
    e->nameLen     = (DWORD)StrLen(zipName);
    e->crc32       = crc;
    e->fileSize    = fileSize;
    e->localOffset = g_offset;
    e->dosTime     = dosTime;
    e->dosDate     = dosDate;

    LocalFileHeader lfh;
    KERNEL32$RtlZeroMemory(&lfh, sizeof(lfh));
    lfh.sig        = ZIP_LFH_SIG;
    lfh.verNeeded  = ZIP_VER;
    lfh.method     = ZIP_STORED;
    lfh.modTime    = dosTime;
    lfh.modDate    = dosDate;
    lfh.crc32      = crc;
    lfh.compSize   = fileSize;
    lfh.uncompSize = fileSize;
    lfh.nameLen    = (WORD)e->nameLen;
    lfh.extraLen   = 0;
    ZipWrite(&lfh, sizeof(lfh));
    ZipWrite(zipName, e->nameLen);
    if (buf && fileSize > 0) {
        ZipWrite(buf, fileSize);
        KERNEL32$HeapFree(g_heap, 0, buf);
    }

    g_count++;
    BeaconPrintf(CALLBACK_OUTPUT, "  added: %s (%lu bytes)\n", zipName, fileSize);
    return TRUE;
}

/* ===== Recursive directory walker ===== */
static void WalkDir(const char *fsBase, const char *zipBase) {
    char pattern[MAX_PATH];
    StrCpy(pattern, fsBase, MAX_PATH);
    StrCat(pattern, "\\*", MAX_PATH);

    WCHAR *wPat = ToWide(pattern);
    if (!wPat) return;

    WIN32_FIND_DATAW fd;
    HANDLE hFind = KERNEL32$FindFirstFileW(wPat, &fd);
    KERNEL32$HeapFree(g_heap, 0, wPat);

    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        /* Convert wide name to ANSI */
        char name[MAX_PATH];
        KERNEL32$WideCharToMultiByte(CP_ACP, 0, fd.cFileName, -1, name, MAX_PATH, NULL, NULL);

        if (name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0')))
            continue;

        char fsPath[MAX_PATH], zipPath[MAX_PATH];
        StrCpy(fsPath,  fsBase,  MAX_PATH);
        StrCat(fsPath,  "\\",    MAX_PATH);
        StrCat(fsPath,  name,    MAX_PATH);

        if (zipBase[0]) {
            StrCpy(zipPath, zipBase, MAX_PATH);
            StrCat(zipPath, "/",     MAX_PATH);
            StrCat(zipPath, name,    MAX_PATH);
        } else {
            StrCpy(zipPath, name, MAX_PATH);
        }

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            WalkDir(fsPath, zipPath);
        } else {
            AddFile(zipPath, fsPath);
        }
    } while (KERNEL32$FindNextFileW(hFind, &fd));

    KERNEL32$FindClose(hFind);
}

void go(IN PCHAR Buffer, IN ULONG Length) {
    datap parser;
    BeaconDataParse(&parser, Buffer, Length);

    int   srcLen  = 0;
    char *srcRaw  = BeaconDataExtract(&parser, &srcLen);
    int   outLen  = 0;
    char *outRaw  = BeaconDataExtract(&parser, &outLen);

    if (!srcRaw || !outRaw || srcLen == 0 || outLen == 0) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: zip <source_path> <output.zip>\n");
        return;
    }

    char src[MAX_PATH], out[MAX_PATH];
    StrCpy(src, srcRaw, MAX_PATH);
    StrCpy(out, outRaw, MAX_PATH);

    g_heap = KERNEL32$GetProcessHeap();

    g_entries = (ZipEntry*)KERNEL32$HeapAlloc(g_heap, HEAP_ZERO_MEMORY,
        MAX_ENTRIES * sizeof(ZipEntry));
    if (!g_entries) {
        BeaconPrintf(CALLBACK_ERROR, "zip: OOM for entry table\n");
        return;
    }

    WCHAR *wOut = ToWide(out);
    if (!wOut) { KERNEL32$HeapFree(g_heap, 0, g_entries); return; }

    g_hZip = KERNEL32$CreateFileW(wOut, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    KERNEL32$HeapFree(g_heap, 0, wOut);

    if (g_hZip == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "zip: cannot create %s (err %lu)\n",
            out, KERNEL32$GetLastError());
        KERNEL32$HeapFree(g_heap, 0, g_entries);
        return;
    }

    g_count  = 0;
    g_offset = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Zipping: %s -> %s\n", src, out);

    WCHAR *wSrc = ToWide(src);
    DWORD attrs = 0;
    if (wSrc) {
        WIN32_FIND_DATAW tmpFd;
        HANDLE h = KERNEL32$FindFirstFileW(wSrc, &tmpFd);
        if (h != INVALID_HANDLE_VALUE) {
            attrs = tmpFd.dwFileAttributes;
            KERNEL32$FindClose(h);
        }
        KERNEL32$HeapFree(g_heap, 0, wSrc);
    }

    if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
        const char *baseName = src;
        for (int i = StrLen(src) - 1; i >= 0; i--) {
            if (src[i] == '\\' || src[i] == '/') { baseName = src + i + 1; break; }
        }
        WalkDir(src, baseName);
    } else {
        const char *fname = src;
        for (int i = StrLen(src) - 1; i >= 0; i--) {
            if (src[i] == '\\' || src[i] == '/') { fname = src + i + 1; break; }
        }
        AddFile(fname, src);
    }

    DWORD cdOffset = g_offset;
    for (DWORD i = 0; i < g_count; i++) {
        ZipEntry *e = &g_entries[i];
        CentralDirHeader cdh;
        KERNEL32$RtlZeroMemory(&cdh, sizeof(cdh));
        cdh.sig         = ZIP_CDH_SIG;
        cdh.verMadeBy   = ZIP_VER;
        cdh.verNeeded   = ZIP_VER;
        cdh.method      = ZIP_STORED;
        cdh.modTime     = e->dosTime;
        cdh.modDate     = e->dosDate;
        cdh.crc32       = e->crc32;
        cdh.compSize    = e->fileSize;
        cdh.uncompSize  = e->fileSize;
        cdh.nameLen     = (WORD)e->nameLen;
        cdh.extraLen    = 0;
        cdh.commentLen  = 0;
        cdh.diskStart   = 0;
        cdh.intAttr     = 0;
        cdh.extAttr     = 0;
        cdh.localOffset = e->localOffset;
        ZipWrite(&cdh, sizeof(cdh));
        ZipWrite(e->name, e->nameLen);
    }

    DWORD cdSize = g_offset - cdOffset;
    EndOfCentralDir eocd;
    KERNEL32$RtlZeroMemory(&eocd, sizeof(eocd));
    eocd.sig          = ZIP_EOCD_SIG;
    eocd.diskNum      = 0;
    eocd.startDisk    = 0;
    eocd.entriesOnDisk = (WORD)g_count;
    eocd.totalEntries  = (WORD)g_count;
    eocd.cdSize        = cdSize;
    eocd.cdOffset      = cdOffset;
    eocd.commentLen    = 0;
    ZipWrite(&eocd, sizeof(eocd));

    KERNEL32$CloseHandle(g_hZip);
    KERNEL32$HeapFree(g_heap, 0, g_entries);

    BeaconPrintf(CALLBACK_OUTPUT,
        "[+] Done: %lu file(s) -> %s (%lu bytes)\n", g_count, out, g_offset);
}
