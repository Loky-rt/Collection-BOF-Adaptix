#include <windows.h>
#include "beacon.h"

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeNameA(LPCSTR, PLUID, LPSTR, LPDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR, LPCSTR, PLUID);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);

static int bof_strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static int bof_strlen(const char *s) {
    int n = 0; while (s[n]) n++; return n;
}

static const char *attr_str(DWORD attr) {
    if (attr & SE_PRIVILEGE_ENABLED)
        return "Enabled";
    if (attr & SE_PRIVILEGE_ENABLED_BY_DEFAULT)
        return "Default";
    return "Disabled";
}


void go(IN PCHAR Buffer, IN ULONG Length) {

    datap parser;
    BeaconDataParse(&parser, Buffer, Length);

    int list_only = BeaconDataInt(&parser);
    char *priv_name = BeaconDataExtract(&parser, NULL);

    int specific = (priv_name && priv_name[0] != '\0');


    HANDLE hToken = NULL;
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(),
                                   TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                                   &hToken)) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] OpenProcessToken failed: %lu\n", KERNEL32$GetLastError());
        return;
    }

    DWORD needed = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &needed);
    if (!needed) {
        BeaconPrintf(CALLBACK_ERROR, "[-] GetTokenInformation (size) failed: %lu\n",
            KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hToken);
        return;
    }

    TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES *)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (!tp) {
        BeaconPrintf(CALLBACK_ERROR, "[-] HeapAlloc failed\n");
        KERNEL32$CloseHandle(hToken);
        return;
    }

    if (!ADVAPI32$GetTokenInformation(hToken, TokenPrivileges, tp, needed, &needed)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] GetTokenInformation failed: %lu\n",
            KERNEL32$GetLastError());
        HeapFree(GetProcessHeap(), 0, tp);
        KERNEL32$CloseHandle(hToken);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "\n[*] Token Privileges (%lu found)\n"
        "    %-45s  %-10s  %s\n"
        "    %-45s  %-10s  %s\n",
        tp->PrivilegeCount,
        "Privilege", "State", "Action",
        "-------------------------------------------",
        "----------", "------");

    int enabled_count  = 0;
    int disabled_count = 0;
    int failed_count   = 0;

    for (DWORD i = 0; i < tp->PrivilegeCount; i++) {
        LUID_AND_ATTRIBUTES *la = &tp->Privileges[i];

        char name[256] = {0};
        DWORD name_len = sizeof(name);
        ADVAPI32$LookupPrivilegeNameA(NULL, &la->Luid, name, &name_len);

        BOOL is_enabled  = (la->Attributes & SE_PRIVILEGE_ENABLED) != 0;
        const char *state = attr_str(la->Attributes);

        if (specific && bof_strcmp(name, priv_name) != 0) {
            if (is_enabled) enabled_count++;
            continue;
        }

        if (list_only == 1) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "    %-45s  %-10s  (skipped — list only)\n", name, state);
            if (is_enabled) enabled_count++;
            else disabled_count++;
            continue;
        }

        if (is_enabled) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "    %-45s  %-10s  -\n", name, state);
            enabled_count++;
            continue;
        }

        disabled_count++;

        TOKEN_PRIVILEGES new_tp;
        new_tp.PrivilegeCount           = 1;
        new_tp.Privileges[0].Luid       = la->Luid;
        new_tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        BOOL ok = ADVAPI32$AdjustTokenPrivileges(
            hToken, FALSE, &new_tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

        DWORD err = KERNEL32$GetLastError();

        if (!ok || err == ERROR_NOT_ALL_ASSIGNED) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "    %-45s  %-10s  [FAILED — err %lu]\n", name, state, err);
            failed_count++;
        } else {
            BeaconPrintf(CALLBACK_OUTPUT,
                "    %-45s  %-10s  [ENABLED]\n", name, state);
        }
    }

    if (list_only == 1) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "\n[*] Summary: %d enabled, %d disabled (list-only mode — none changed)\n",
            enabled_count, disabled_count);
    } else if (specific) {
        if (disabled_count == 0) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "\n[*] '%s' is already enabled or not present in this token.\n",
                priv_name);
        } else if (failed_count == 0) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "\n[+] '%s' enabled successfully.\n", priv_name);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT,
                "\n[-] Failed to enable '%s' (privilege may not be assigned to this token).\n",
                priv_name);
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
            "\n[*] Summary: %d already enabled, %d disabled — %d enabled now, %d failed\n",
            enabled_count,
            disabled_count,
            disabled_count - failed_count,
            failed_count);
        if (failed_count > 0) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "    Note: failed privileges are assigned but cannot be elevated\n"
                "    from the current integrity level.\n");
        }
    }

    HeapFree(GetProcessHeap(), 0, tp);
    KERNEL32$CloseHandle(hToken);
}
