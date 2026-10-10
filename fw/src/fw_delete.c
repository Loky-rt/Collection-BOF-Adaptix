// fw_delete.c — Delete a Windows Firewall rule via registry
//
// Usage from AXS:
//   fw_delete /name:<rule_name> [/host:HOSTNAME]
//
// Deletes the registry value whose name matches exactly.
// For wildcard/pattern delete, use fw_find first to identify names.

#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include "fw_common.c"

static DWORD fw_delete(const char *hostname, const char *name) {
    if (!name || !name[0]) {
        internal_printf("[-] Rule name is required.\n");
        return ERROR_INVALID_PARAMETER;
    }

    HKEY hKey = NULL, hRemote = NULL;
    LONG rc = fw_open_key(hostname, KEY_SET_VALUE | KEY_READ, &hKey, &hRemote);
    if (rc != ERROR_SUCCESS) {
        internal_printf("[-] Failed to open firewall registry key (error %ld)\n", (long)rc);
        if (rc == ERROR_ACCESS_DENIED)
            internal_printf("    Hint: deleting firewall rules requires Administrator.\n");
        goto END;
    }

    // Verify the rule exists first
    DWORD existSz = 0;
    LONG existRc = ADVAPI32$RegQueryValueExA(hKey, name, NULL, NULL, NULL, &existSz);
    if (existRc != ERROR_SUCCESS) {
        internal_printf("[-] Rule '%s' not found (error %ld)\n", name, (long)existRc);
        rc = existRc;
        goto END;
    }

    rc = ADVAPI32$RegDeleteValueA(hKey, name);
    if (rc == ERROR_SUCCESS) {
        internal_printf("[+] Rule '%s' deleted successfully.\n", name);
    } else {
        internal_printf("[-] Failed to delete rule '%s' (error %ld)\n", name, (long)rc);
    }

END:
    fw_close_key(hKey, hRemote);
    return (DWORD)rc;
}

// -----------------------------------------------------------------------
// Entry point
// -----------------------------------------------------------------------
#ifdef BOF

VOID go(IN PCHAR Buffer, IN ULONG Length) {
    datap       parser   = {0};
    const char *hostname = NULL;
    const char *name     = NULL;

    BeaconDataParse(&parser, Buffer, Length);
    hostname = BeaconDataExtract(&parser, NULL);
    name     = BeaconDataExtract(&parser, NULL);

    if (hostname && *hostname == 0) hostname = NULL;

    if (!name || !*name) {
        BeaconPrintf(CALLBACK_ERROR, "Rule name required (-n <name>)");
        return;
    }

    if (!bofstart()) return;

    fw_delete(hostname, name);

    printoutput(TRUE);
    bofstop();
}

#else

int main() {
    bofstart();
    fw_delete(NULL, "TestRule_TCP4444");
    fw_delete(NULL, "TestRule_BlockDNS");
    fw_delete(NULL, "NonExistentRule");  // should print not found
    printoutput(TRUE);
    bofstop();
    return 0;
}

#endif
