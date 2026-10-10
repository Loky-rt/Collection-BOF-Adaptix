#include <windows.h>
#include "beacon.h"

#define LOG_INFO(fmt, ...)  ( BeaconPrintf(CALLBACK_OUTPUT, fmt, ##__VA_ARGS__) )
#define LOG_ERROR(fmt, ...) ( BeaconPrintf(CALLBACK_ERROR, fmt, ##__VA_ARGS__) )

WINBASEAPI HANDLE   WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
WINBASEAPI BOOL     WINAPI KERNEL32$GetFileTime(HANDLE, LPFILETIME, LPFILETIME, LPFILETIME);
WINBASEAPI BOOL     WINAPI KERNEL32$SetFileTime(HANDLE, const FILETIME*, const FILETIME*, const FILETIME*);
WINBASEAPI BOOL     WINAPI KERNEL32$CloseHandle(HANDLE);
WINBASEAPI DWORD    WINAPI KERNEL32$GetLastError(void);

void go(char* args, int alen)
{
    datap parser;
    int target_len = 0;
    int source_len = 0;
    char* target_file = NULL;
    char* source_file = NULL;

    HANDLE hTarget = INVALID_HANDLE_VALUE;
    HANDLE hSource = INVALID_HANDLE_VALUE;
    FILETIME ftCreation, ftAccess, ftWrite;
    BOOL success = FALSE;

    /* Parse arguments: target_file source_file */
    BeaconDataParse(&parser, args, alen);
    target_file = BeaconDataExtract(&parser, &target_len);
    source_file = BeaconDataExtract(&parser, &source_len);

    if (!target_file || target_len == 0) {
        LOG_ERROR("[-] Usage: timestomp <target_file> <source_file>\n");
        return;
    }

    if (!source_file || source_len == 0) {
        LOG_ERROR("[-] Usage: timestomp <target_file> <source_file>\n");
        return;
    }

    LOG_INFO("[*] Target  : %s\n", target_file);
    LOG_INFO("[*] Source  : %s\n", source_file);

    /* Open source file to read its timestamps */
    hSource = KERNEL32$CreateFileA(source_file,
                                    FILE_READ_ATTRIBUTES,
                                    FILE_SHARE_READ,
                                    NULL,
                                    OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL,
                                    NULL);
    if (hSource == INVALID_HANDLE_VALUE) {
        LOG_ERROR("[-] Failed to open source file (error %lu)\n",
                  KERNEL32$GetLastError());
        return;
    }

    /* Read timestamps from source */
    if (!KERNEL32$GetFileTime(hSource, &ftCreation, &ftAccess, &ftWrite)) {
        LOG_ERROR("[-] Failed to read timestamps from source (error %lu)\n",
                  KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hSource);
        return;
    }

    KERNEL32$CloseHandle(hSource);

    LOG_INFO("[+] Read timestamps from source:\n");
    LOG_INFO("    Creation: 0x%08x%08x\n",
             ftCreation.dwHighDateTime, ftCreation.dwLowDateTime);
    LOG_INFO("    Access  : 0x%08x%08x\n",
             ftAccess.dwHighDateTime, ftAccess.dwLowDateTime);
    LOG_INFO("    Write   : 0x%08x%08x\n",
             ftWrite.dwHighDateTime, ftWrite.dwLowDateTime);

    /* Open target file for writing */
    hTarget = KERNEL32$CreateFileA(target_file,
                                    FILE_WRITE_ATTRIBUTES,
                                    FILE_SHARE_WRITE,
                                    NULL,
                                    OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL,
                                    NULL);
    if (hTarget == INVALID_HANDLE_VALUE) {
        LOG_ERROR("[-] Failed to open target file (error %lu)\n",
                  KERNEL32$GetLastError());
        return;
    }

    /* Write timestamps to target */
    if (!KERNEL32$SetFileTime(hTarget, &ftCreation, &ftAccess, &ftWrite)) {
        LOG_ERROR("[-] Failed to set timestamps on target (error %lu)\n",
                  KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hTarget);
        return;
    }

    KERNEL32$CloseHandle(hTarget);

    LOG_INFO("[+] Successfully applied timestamps from source to target\n");
}