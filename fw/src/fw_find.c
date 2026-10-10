// fw_find.c — Search Windows Firewall rules by pattern
//
// Usage from AXS:
//   fw_find /pattern:<text> [/field:name|app|port|any] [/host:HOSTNAME]
//
// search_field:
//   0 = name (default)
//   1 = app path
//   2 = port (LPort or RPort)
//   3 = any field (name + app + ports + desc)
//
// Case-insensitive substring match.

#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include "fw_common.c"

static DWORD fw_find(const char *hostname,
                     const char *pattern,
                     int          search_field) {
    if (!pattern || !pattern[0]) {
        internal_printf("[-] Search pattern is required.\n");
        return ERROR_INVALID_PARAMETER;
    }

    HKEY hKey = NULL, hRemote = NULL;
    LONG rc = fw_open_key(hostname, KEY_READ, &hKey, &hRemote);
    if (rc != ERROR_SUCCESS) {
        internal_printf("[-] Failed to open firewall registry key (error %ld)\n", (long)rc);
        goto END;
    }

    DWORD numValues  = 0;
    DWORD maxNameLen = 0;
    DWORD maxDataLen = 0;

    rc = ADVAPI32$RegQueryInfoKeyA(hKey, NULL, NULL, NULL, NULL, NULL, NULL,
                                   &numValues, &maxNameLen, &maxDataLen,
                                   NULL, NULL);
    if (rc != ERROR_SUCCESS) {
        internal_printf("[-] RegQueryInfoKey failed (error %ld)\n", (long)rc);
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

    const char *field_label = "name";
    if      (search_field == 1) field_label = "app";
    else if (search_field == 2) field_label = "port";
    else if (search_field == 3) field_label = "any field";

    internal_printf("[*] Searching for '%s' in %s...\n\n", pattern, field_label);

    DWORD matches = 0;
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
        if (valName[0] == '\0')  continue;

        char name[256]     = {0};
        char app[MAX_PATH] = {0};
        char lport[64]     = {0};
        char rport[64]     = {0};
        char desc[256]     = {0};

        fw_get_field(valData, "Name",  name,  sizeof(name));
        fw_get_field(valData, "App",   app,   sizeof(app));
        fw_get_field(valData, "LPort", lport, sizeof(lport));
        fw_get_field(valData, "RPort", rport, sizeof(rport));
        fw_get_field(valData, "Desc",  desc,  sizeof(desc));

        BOOL hit = FALSE;
        switch (search_field) {
            case 0: // name
                hit = fw_stristr(name, pattern);
                break;
            case 1: // app
                hit = fw_stristr(app, pattern);
                break;
            case 2: // port
                hit = fw_stristr(lport, pattern) || fw_stristr(rport, pattern);
                break;
            case 3: // any
                hit = fw_stristr(name,  pattern) ||
                      fw_stristr(app,   pattern) ||
                      fw_stristr(lport, pattern) ||
                      fw_stristr(rport, pattern) ||
                      fw_stristr(desc,  pattern);
                break;
        }

        if (!hit) continue;

        if (matches == 0) fw_print_header();
        fw_print_rule(valName, valData);

        // Show full app path if it was matched or truncated
        if (app[0] && (search_field == 1 || search_field == 3))
            internal_printf("    App: %s\n", app);

        matches++;
    }

    if (matches == 0)
        internal_printf("[-] No rules found matching '%s'.\n", pattern);
    else
        internal_printf("\n[*] %lu match(es) found.\n", (unsigned long)matches);

    intFree(valName);
    intFree(valData);

END:
    fw_close_key(hKey, hRemote);
    return (rc == ERROR_SUCCESS || matches > 0) ? 0 : (DWORD)rc;
}

// -----------------------------------------------------------------------
// Entry point
// -----------------------------------------------------------------------
#ifdef BOF

VOID go(IN PCHAR Buffer, IN ULONG Length) {
    datap       parser       = {0};
    const char *hostname     = NULL;
    const char *pattern      = NULL;
    int         search_field = 0;

    BeaconDataParse(&parser, Buffer, Length);
    hostname     = BeaconDataExtract(&parser, NULL);
    pattern      = BeaconDataExtract(&parser, NULL);
    search_field = BeaconDataInt(&parser);

    if (hostname && *hostname == 0) hostname = NULL;

    if (!pattern || !*pattern) {
        BeaconPrintf(CALLBACK_ERROR, "Search pattern required (-s <pattern>)");
        return;
    }

    if (!bofstart()) return;

    fw_find(hostname, pattern, search_field);

    printoutput(TRUE);
    bofstop();
}

#else

int main() {
    bofstart();
    fw_find(NULL, "Remote Desktop", 0);   // search by name
    fw_find(NULL, "svchost",        1);   // search by app
    fw_find(NULL, "445",            2);   // search by port
    fw_find(NULL, "chrome",         3);   // search any field
    printoutput(TRUE);
    bofstop();
    return 0;
}

#endif
