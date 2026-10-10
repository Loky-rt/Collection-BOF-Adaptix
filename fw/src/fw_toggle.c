// fw_toggle.c — Enable or disable a Windows Firewall rule
//
// Usage from AXS:
//   fw_toggle /name:<rule_name> /state:enable|disable [/host:HOSTNAME]
//
// Reads the existing rule string, flips Active=TRUE/FALSE, writes it back.
// Non-destructive — all other fields preserved exactly.

#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include "fw_common.c"

static DWORD fw_toggle(const char *hostname,
                        const char *name,
                        BOOL        enable) {
    if (!name || !name[0]) {
        internal_printf("[-] Rule name is required.\n");
        return ERROR_INVALID_PARAMETER;
    }

    HKEY hKey = NULL, hRemote = NULL;
    LONG rc = fw_open_key(hostname, KEY_SET_VALUE | KEY_READ, &hKey, &hRemote);
    if (rc != ERROR_SUCCESS) {
        internal_printf("[-] Failed to open firewall registry key (error %ld)\n", (long)rc);
        if (rc == ERROR_ACCESS_DENIED)
            internal_printf("    Hint: modifying firewall rules requires Administrator.\n");
        goto END;
    }

    // Query existing rule size
    DWORD existSz = 0;
    DWORD existType = 0;
    rc = ADVAPI32$RegQueryValueExA(hKey, name, NULL, &existType, NULL, &existSz);
    if (rc != ERROR_SUCCESS) {
        internal_printf("[-] Rule '%s' not found (error %ld)\n", name, (long)rc);
        goto END;
    }
    if (existType != REG_SZ) {
        internal_printf("[-] Unexpected value type for rule '%s'.\n", name);
        rc = ERROR_INVALID_DATA;
        goto END;
    }

    // Read existing rule
    char *oldRule = (char *)intAlloc(existSz + 4);
    if (!oldRule) {
        internal_printf("[-] Memory allocation failed.\n");
        rc = ERROR_OUTOFMEMORY;
        goto END;
    }
    rc = ADVAPI32$RegQueryValueExA(hKey, name, NULL, NULL, (LPBYTE)oldRule, &existSz);
    if (rc != ERROR_SUCCESS) {
        internal_printf("[-] Failed to read rule (error %ld)\n", (long)rc);
        intFree(oldRule);
        goto END;
    }

    // Build new rule string with Active flipped
    // Strategy: copy everything, replace Active=TRUE|/Active=FALSE|
    char *newRule = (char *)intAlloc(existSz + 16);
    if (!newRule) {
        internal_printf("[-] Memory allocation failed.\n");
        intFree(oldRule);
        rc = ERROR_OUTOFMEMORY;
        goto END;
    }

    const char *src  = oldRule;
    char       *dst  = newRule;
    BOOL        done = FALSE;

    while (*src) {
        // Look for Active= field
        if (!done &&
            fw_strncmp(src, "Active=", 7) == 0) {
            // Copy "Active="
            const char *tag = "Active=";
            while (*tag) *dst++ = *tag++;
            // Write new value
            const char *newval = enable ? "TRUE" : "FALSE";
            while (*newval) *dst++ = *newval++;
            // Skip old value until next '|' or end
            src += 7;
            while (*src && *src != '|') src++;
            done = TRUE;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';

    if (!done) {
        // Active= field not found — append it before closing |
        // (shouldn't happen with valid rules, but handle gracefully)
        internal_printf("[!] Active field not found in rule, appending.\n");
        // Find end before final | or just append
        int nlen = fw_strlen(newRule);
        if (nlen > 0 && newRule[nlen-1] == '|') nlen--;
        const char *append = enable ? "|Active=TRUE|" : "|Active=FALSE|";
        int alen = fw_strlen(append);
        MSVCRT$memcpy(newRule + nlen, append, alen + 1);
    }

    DWORD newLen = (DWORD)fw_strlen(newRule) + 1;
    rc = ADVAPI32$RegSetValueExA(hKey, name, 0, REG_SZ,
                                  (const BYTE *)newRule, newLen);
    if (rc == ERROR_SUCCESS) {
        internal_printf("[+] Rule '%s' %s.\n",
            name, enable ? "enabled" : "disabled");
    } else {
        internal_printf("[-] Failed to update rule (error %ld)\n", (long)rc);
    }

    intFree(oldRule);
    intFree(newRule);

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
    int         enable_i = 1;  // 1 = enable, 0 = disable

    BeaconDataParse(&parser, Buffer, Length);
    hostname = BeaconDataExtract(&parser, NULL);
    name     = BeaconDataExtract(&parser, NULL);
    enable_i = BeaconDataInt(&parser);

    if (hostname && *hostname == 0) hostname = NULL;

    if (!name || !*name) {
        BeaconPrintf(CALLBACK_ERROR, "Rule name required (-n <name>)");
        return;
    }

    if (!bofstart()) return;

    fw_toggle(hostname, name, enable_i != 0);

    printoutput(TRUE);
    bofstop();
}

#else

int main() {
    bofstart();
    fw_toggle(NULL, "TestRule_TCP4444", FALSE);  // disable
    fw_toggle(NULL, "TestRule_TCP4444", TRUE);   // re-enable
    printoutput(TRUE);
    bofstop();
    return 0;
}

#endif
