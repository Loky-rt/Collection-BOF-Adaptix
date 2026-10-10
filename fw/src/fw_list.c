// fw_list.c — List Windows Firewall rules via registry
//
// Usage from AXS:
//   fw_list [/host:HOSTNAME] [/dir:In|Out] [/action:Allow|Block] [/active:true|false]
//
// All filters are optional and combinable.

#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include "fw_common.c"

// -----------------------------------------------------------------------
// List rules with optional filters
// Pass NULL/empty string to skip a filter
// -----------------------------------------------------------------------
static DWORD fw_list(const char *hostname,
                     const char *filter_dir,
                     const char *filter_action,
                     const char *filter_active,
                     const char *filter_name) {
    HKEY hKey = NULL, hRemote = NULL;
    LONG rc = fw_open_key(hostname, KEY_READ, &hKey, &hRemote);
    if (rc != ERROR_SUCCESS) {
        internal_printf("[-] Failed to open firewall registry key (error %ld)\n", (long)rc);
        if (rc == ERROR_ACCESS_DENIED)
            internal_printf("    Hint: listing firewall rules requires SYSTEM or Administrator.\n");
        goto END;
    }

    DWORD numValues    = 0;
    DWORD maxNameLen   = 0;
    DWORD maxDataLen   = 0;

    rc = ADVAPI32$RegQueryInfoKeyA(hKey, NULL, NULL, NULL, NULL, NULL, NULL,
                                   &numValues, &maxNameLen, &maxDataLen,
                                   NULL, NULL);
    if (rc != ERROR_SUCCESS) {
        internal_printf("[-] RegQueryInfoKey failed (error %ld)\n", (long)rc);
        goto END;
    }

    if (numValues == 0) {
        internal_printf("[*] No firewall rules found.\n");
        goto END;
    }

    char *valName = (char *)intAlloc(maxNameLen + 2);
    char *valData = (char *)intAlloc(maxDataLen + 2);
    if (!valName || !valData) {
        internal_printf("[-] Memory allocation failed.\n");
        if (valName) intFree(valName);
        if (valData) intFree(valData);
        goto END;
    }

    fw_print_header();

    DWORD matched = 0;
    for (DWORD i = 0; i < numValues; i++) {
        DWORD vnLen = maxNameLen + 1;
        DWORD vdLen = maxDataLen + 2;
        DWORD vType = 0;
        MSVCRT$memset(valName, 0, maxNameLen + 2);
        MSVCRT$memset(valData, 0, maxDataLen + 2);

        rc = ADVAPI32$RegEnumValueA(hKey, i, valName, &vnLen,
                                    NULL, &vType,
                                    (LPBYTE)valData, &vdLen);
        if (rc != ERROR_SUCCESS) continue;
        if (vType != REG_SZ)     continue;

        // Skip the default "(Default)" value if present
        if (valName[0] == '\0')  continue;

        // Apply filters
        if (filter_dir && filter_dir[0]) {
            char dir[8] = {0};
            fw_get_field(valData, "Dir", dir, sizeof(dir));
            if (fw_stricmp(dir, filter_dir) != 0) continue;
        }
        if (filter_action && filter_action[0]) {
            char action[16] = {0};
            fw_get_field(valData, "Action", action, sizeof(action));
            if (fw_stricmp(action, filter_action) != 0) continue;
        }
        if (filter_active && filter_active[0]) {
            char active[8] = {0};
            fw_get_field(valData, "Active", active, sizeof(active));
            if (fw_stricmp(active, filter_active) != 0) continue;
        }
        if (filter_name && filter_name[0]) {
            char name[256] = {0};
            fw_get_field(valData, "Name", name, sizeof(name));
            if (!fw_stristr(name, filter_name)) continue;
        }

        fw_print_rule(valName, valData);
        matched++;
    }

    internal_printf("\n[*] %lu rule(s) shown (total: %lu)\n",
                    (unsigned long)matched, (unsigned long)numValues);

    intFree(valName);
    intFree(valData);

END:
    fw_close_key(hKey, hRemote);
    return (rc == ERROR_SUCCESS || rc == 0) ? 0 : (DWORD)rc;
}

// -----------------------------------------------------------------------
// Entry point
// -----------------------------------------------------------------------
#ifdef BOF

VOID go(IN PCHAR Buffer, IN ULONG Length) {
    datap       parser      = {0};
    const char *hostname    = NULL;
    const char *dir         = NULL;
    const char *action      = NULL;
    const char *active      = NULL;
    const char *name_filter = NULL;

    BeaconDataParse(&parser, Buffer, Length);
    hostname    = BeaconDataExtract(&parser, NULL);
    dir         = BeaconDataExtract(&parser, NULL);
    action      = BeaconDataExtract(&parser, NULL);
    active      = BeaconDataExtract(&parser, NULL);
    name_filter = BeaconDataExtract(&parser, NULL);

    if (hostname    && *hostname    == 0) hostname    = NULL;
    if (dir         && *dir         == 0) dir         = NULL;
    if (action      && *action      == 0) action      = NULL;
    if (active      && *active      == 0) active      = NULL;
    if (name_filter && *name_filter == 0) name_filter = NULL;

    if (!bofstart()) return;

    internal_printf("[*] Firewall rules%s%s\n",
        hostname ? " on " : " (local)",
        hostname ? hostname : "");

    fw_list(hostname, dir, action, active, name_filter);

    printoutput(TRUE);
    bofstop();
}

#else

int main() {
    bofstart();
    fw_list(NULL, NULL,  NULL,    NULL, NULL);      // all rules
    fw_list(NULL, "In",  "Block", NULL, NULL);      // inbound blocks
    fw_list(NULL, NULL,  NULL,    NULL, "Remote");  // name contains "Remote"
    printoutput(TRUE);
    bofstop();
    return 0;
}

#endif
