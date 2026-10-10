// fw_add.c — Add a Windows Firewall rule via registry
//
// Usage from AXS:
//   fw_add /name:<name> [/action:Allow|Block] [/dir:In|Out]
//          [/proto:6|17|256] [/lport:<port>] [/rport:<port>]
//          [/app:<path>] [/profile:2147483647] [/desc:<text>]
//          [/active:TRUE|FALSE] [/host:HOSTNAME]
//
// The rule value name in the registry is the same as the display name.
// Windows uses a GUID as value name internally, but plain names work too.

#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include "fw_common.c"

static DWORD fw_add(const char *hostname,
                    const char *name,
                    const char *action,
                    const char *dir,
                    const char *protocol,
                    const char *lport,
                    const char *rport,
                    const char *app,
                    const char *profile,
                    const char *desc,
                    BOOL        active) {
    if (!name || !name[0]) {
        internal_printf("[-] Rule name is required.\n");
        return ERROR_INVALID_PARAMETER;
    }

    HKEY hKey = NULL, hRemote = NULL;
    LONG rc = fw_open_key(hostname, KEY_SET_VALUE | KEY_READ, &hKey, &hRemote);
    if (rc != ERROR_SUCCESS) {
        internal_printf("[-] Failed to open firewall registry key (error %ld)\n", (long)rc);
        if (rc == ERROR_ACCESS_DENIED)
            internal_printf("    Hint: creating firewall rules requires Administrator.\n");
        goto END;
    }

    // Check if a rule with this name already exists (value name = rule name)
    DWORD existSz = 0;
    LONG existRc = ADVAPI32$RegQueryValueExA(hKey, name, NULL, NULL, NULL, &existSz);
    if (existRc == ERROR_SUCCESS) {
        internal_printf("[!] A rule named '%s' already exists. Delete it first.\n", name);
        rc = ERROR_ALREADY_EXISTS;
        goto END;
    }

    // Build the rule string
    char *ruleStr = fw_build_rule(name, action, dir, protocol,
                                  lport, rport, app, profile, desc, active);
    if (!ruleStr) {
        internal_printf("[-] Memory allocation failed.\n");
        rc = ERROR_OUTOFMEMORY;
        goto END;
    }

    DWORD dataLen = (DWORD)fw_strlen(ruleStr) + 1;
    rc = ADVAPI32$RegSetValueExA(hKey, name, 0, REG_SZ,
                                  (const BYTE *)ruleStr, dataLen);
    intFree(ruleStr);

    if (rc == ERROR_SUCCESS) {
        internal_printf("[+] Firewall rule created:\n");
        internal_printf("    Name    : %s\n", name);
        internal_printf("    Action  : %s\n", action[0]  ? action  : "Allow");
        internal_printf("    Dir     : %s\n", dir[0]     ? dir     : "In");
        internal_printf("    Proto   : %s\n", fw_proto_name(protocol[0] ? protocol : "256"));
        if (lport && lport[0]) internal_printf("    LPort   : %s\n", lport);
        if (rport && rport[0]) internal_printf("    RPort   : %s\n", rport);
        if (app   && app[0])   internal_printf("    App     : %s\n", app);
        internal_printf("    Profile : %s\n", fw_profile_name(profile[0] ? profile : "2147483647"));
        internal_printf("    Active  : %s\n", active ? "TRUE" : "FALSE");
    } else {
        internal_printf("[-] RegSetValueEx failed (error %ld)\n", (long)rc);
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
    const char *action   = NULL;
    const char *dir      = NULL;
    const char *protocol = NULL;
    const char *lport    = NULL;
    const char *rport    = NULL;
    const char *app      = NULL;
    const char *profile  = NULL;
    const char *desc     = NULL;
    int         active_i = 0;

    BeaconDataParse(&parser, Buffer, Length);
    hostname = BeaconDataExtract(&parser, NULL);
    name     = BeaconDataExtract(&parser, NULL);
    action   = BeaconDataExtract(&parser, NULL);
    dir      = BeaconDataExtract(&parser, NULL);
    protocol = BeaconDataExtract(&parser, NULL);
    lport    = BeaconDataExtract(&parser, NULL);
    rport    = BeaconDataExtract(&parser, NULL);
    app      = BeaconDataExtract(&parser, NULL);
    profile  = BeaconDataExtract(&parser, NULL);
    desc     = BeaconDataExtract(&parser, NULL);
    active_i = BeaconDataInt(&parser);  // 1 = TRUE, 0 = FALSE

    // Normalize empty strings to NULL for optional fields
    #define NULLIFY(x) if ((x) && *(x) == 0) (x) = NULL
    NULLIFY(hostname); NULLIFY(action); NULLIFY(dir);
    NULLIFY(protocol); NULLIFY(lport);  NULLIFY(rport);
    NULLIFY(app);      NULLIFY(profile);NULLIFY(desc);
    #undef NULLIFY

    if (!name || !*name) {
        BeaconPrintf(CALLBACK_ERROR, "Rule name required (-n <name>)");
        return;
    }

    if (!bofstart()) return;

    fw_add(hostname,
           name,
           action   ? action   : "Allow",
           dir      ? dir      : "In",
           protocol ? protocol : "256",
           lport    ? lport    : "",
           rport    ? rport    : "",
           app      ? app      : "",
           profile  ? profile  : "2147483647",
           desc     ? desc     : "",
           active_i != 0);

    printoutput(TRUE);
    bofstop();
}

#else

int main() {
    bofstart();
    // Allow inbound TCP 4444
    fw_add(NULL, "TestRule_TCP4444", "Allow", "In", "6",
           "4444", "", "", "2147483647", "Test rule", TRUE);
    // Block outbound UDP 53
    fw_add(NULL, "TestRule_BlockDNS", "Block", "Out", "17",
           "", "53", "", "2147483647", "Block DNS", TRUE);
    printoutput(TRUE);
    bofstop();
    return 0;
}

#endif
