// fw_common.c — shared helpers for firewall BOF modules
// Included directly by each module (not compiled separately)
//
// Registry path where Windows Firewall rules live:
//   HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules
//
// Each value is a REG_SZ with format (v2.10):
//   v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=4444|Name=MyRule|Desc=...|App=...|
//
// Fields we care about:
//   Action   = Allow | Block
//   Active   = TRUE | FALSE
//   Dir      = In | Out
//   Protocol = 6 (TCP) | 17 (UDP) | 1 (ICMP) | 256 (Any)
//   LPort    = local port or range
//   RPort    = remote port or range
//   Name     = display name
//   Desc     = description
//   App      = application path
//   Profile  = 1 (Domain) | 2 (Private) | 4 (Public) | 2147483647 (Any)
//   RA4/RA6  = remote address

#pragma once

#define FW_REG_PATH \
    "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules"

// -----------------------------------------------------------------------
// Safe string helpers — no CRT builtins
// -----------------------------------------------------------------------

// NOTE: pointer arithmetic implementation intentional.
// GCC -Os recognizes the indexed loop (s[n]) as strlen() and emits an
// external symbol that BOF loaders cannot resolve. Pointer form avoids it.
static __attribute__((noinline)) int fw_strlen(const char *s) {
    const char *e = s; while (*e) e++; return (int)(e - s);
}

static __attribute__((noinline)) int fw_strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static __attribute__((noinline)) int fw_strncmp(const char *a, const char *b, int n) {
    int i = 0;
    while (i < n && *a && *b && *a == *b) { a++; b++; i++; }
    if (i == n) return 0;
    return (unsigned char)*a - (unsigned char)*b;
}

// Case-insensitive compare
static __attribute__((noinline)) int fw_stricmp(const char *a, const char *b) {
    while (*a && *b) {
        char ca = (*a >= 'A' && *a <= 'Z') ? *a + 32 : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? *b + 32 : *b;
        if (ca != cb) return (unsigned char)ca - (unsigned char)cb;
        a++; b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

// Case-insensitive substring search
static __attribute__((noinline)) BOOL fw_stristr(const char *hay, const char *needle) {
    if (!needle || !*needle) return TRUE;
    if (!hay)    return FALSE;
    int nlen = fw_strlen(needle);
    int hlen = fw_strlen(hay);
    if (nlen > hlen) return FALSE;
    for (int i = 0; i <= hlen - nlen; i++) {
        int j = 0;
        while (j < nlen) {
            char hc = hay[i+j]; char nc = needle[j];
            if (hc >= 'A' && hc <= 'Z') hc += 32;
            if (nc >= 'A' && nc <= 'Z') nc += 32;
            if (hc != nc) break;
            j++;
        }
        if (j == nlen) return TRUE;
    }
    return FALSE;
}

static void fw_strcpy(char *dst, const char *src) {
    while ((*dst++ = *src++));
}

static void fw_strncpy(char *dst, const char *src, int n) {
    int i = 0;
    while (i < n - 1 && src[i]) { dst[i] = src[i]; i++; }
    dst[i] = '\0';
}

// -----------------------------------------------------------------------
// Rule field extractor
// Given the full rule value string and a field name (e.g. "Name"),
// copies the value into out (max outlen chars). Returns TRUE if found.
//
// Format: ...|FieldName=Value|...
// -----------------------------------------------------------------------
static BOOL fw_get_field(const char *rule, const char *field,
                         char *out, int outlen) {
    out[0] = '\0';
    int flen = fw_strlen(field);
    const char *p = rule;

    while (*p) {
        // skip to next '|' separator or start of string
        if (fw_strncmp(p, field, flen) == 0 && p[flen] == '=') {
            const char *val = p + flen + 1;
            int i = 0;
            while (val[i] && val[i] != '|' && i < outlen - 1) {
                out[i] = val[i]; i++;
            }
            out[i] = '\0';
            return TRUE;
        }
        // advance to next field
        while (*p && *p != '|') p++;
        if (*p == '|') p++;
    }
    return FALSE;
}

// -----------------------------------------------------------------------
// Build a minimal rule string from components.
// Returns allocated string (caller must intFree).
// profile: 1=Domain, 2=Private, 4=Public, 2147483647=Any
// protocol: 6=TCP, 17=UDP, 256=Any
// -----------------------------------------------------------------------
static char *fw_build_rule(const char *name, const char *action,
                            const char *dir,  const char *protocol,
                            const char *lport, const char *rport,
                            const char *app,   const char *profile,
                            const char *desc,  BOOL active) {
    char *buf = (char *)intAlloc(4096);
    if (!buf) return NULL;

    // Base fields always present
    char *p = buf;
    // We build manually to avoid MSVCRT$sprintf emitting strlen implicitly
    // with %s on some GCC versions — use field-by-field append instead.

    #define FW_APPEND(s) { const char *_s = (s); while (*_s) *p++ = *_s++; }

    FW_APPEND("v2.10|Action=");
    FW_APPEND(action[0] ? action : "Allow");
    FW_APPEND("|Active=");
    FW_APPEND(active ? "TRUE" : "FALSE");
    FW_APPEND("|Dir=");
    FW_APPEND(dir[0] ? dir : "In");
    FW_APPEND("|Protocol=");
    FW_APPEND(protocol[0] ? protocol : "256");

    if (lport && lport[0]) { FW_APPEND("|LPort="); FW_APPEND(lport); }
    if (rport && rport[0]) { FW_APPEND("|RPort="); FW_APPEND(rport); }
    if (app   && app[0])   { FW_APPEND("|App=");   FW_APPEND(app);   }

    FW_APPEND("|Name=");
    FW_APPEND(name);

    if (desc && desc[0]) { FW_APPEND("|Desc="); FW_APPEND(desc); }

    // Profile — default 2147483647 (any)
    FW_APPEND("|Profile=");
    FW_APPEND((profile && profile[0]) ? profile : "2147483647");

    FW_APPEND("|");
    *p = '\0';

    #undef FW_APPEND
    return buf;
}

// -----------------------------------------------------------------------
// Translate protocol number to name
// -----------------------------------------------------------------------
static const char *fw_proto_name(const char *proto) {
    if (fw_strcmp(proto, "6")   == 0) return "TCP";
    if (fw_strcmp(proto, "17")  == 0) return "UDP";
    if (fw_strcmp(proto, "1")   == 0) return "ICMP";
    if (fw_strcmp(proto, "58")  == 0) return "ICMPv6";
    if (fw_strcmp(proto, "256") == 0) return "Any";
    if (proto[0] == '\0')             return "Any";
    return proto;
}

// -----------------------------------------------------------------------
// Translate profile number to name
// -----------------------------------------------------------------------
static const char *fw_profile_name(const char *profile) {
    if (fw_strcmp(profile, "1")          == 0) return "Domain";
    if (fw_strcmp(profile, "2")          == 0) return "Private";
    if (fw_strcmp(profile, "4")          == 0) return "Public";
    if (fw_strcmp(profile, "3")          == 0) return "Domain,Private";
    if (fw_strcmp(profile, "5")          == 0) return "Domain,Public";
    if (fw_strcmp(profile, "6")          == 0) return "Private,Public";
    if (fw_strcmp(profile, "7")          == 0) return "All";
    if (fw_strcmp(profile, "2147483647") == 0) return "Any";
    if (profile[0] == '\0')                    return "Any";
    return profile;
}

// -----------------------------------------------------------------------
// Print one rule in a formatted table row
// -----------------------------------------------------------------------
static void fw_print_rule(const char *value_name, const char *rule) {
    char name[256]     = {0};
    char action[16]    = {0};
    char dir[8]        = {0};
    char active[8]     = {0};
    char proto[8]      = {0};
    char lport[64]     = {0};
    char rport[64]     = {0};
    char profile[16]   = {0};
    char app[MAX_PATH] = {0};

    fw_get_field(rule, "Name",    name,    sizeof(name));
    fw_get_field(rule, "Action",  action,  sizeof(action));
    fw_get_field(rule, "Dir",     dir,     sizeof(dir));
    fw_get_field(rule, "Active",  active,  sizeof(active));
    fw_get_field(rule, "Protocol",proto,   sizeof(proto));
    fw_get_field(rule, "LPort",   lport,   sizeof(lport));
    fw_get_field(rule, "RPort",   rport,   sizeof(rport));
    fw_get_field(rule, "Profile", profile, sizeof(profile));
    fw_get_field(rule, "App",     app,     sizeof(app));

    // Shorten app path to just filename for display
    const char *appname = app;
    if (app[0]) {
        const char *last = app;
        for (const char *q = app; *q; q++)
            if (*q == '\\' || *q == '/') last = q + 1;
        appname = last;
    }

    internal_printf("%-35s %-6s %-4s %-6s %-5s %-10s %-10s %-10s %s\n",
        name[0]    ? name    : value_name,
        action[0]  ? action  : "?",
        dir[0]     ? dir     : "?",
        active[0]  ? active  : "?",
        fw_proto_name(proto),
        lport[0]   ? lport   : "*",
        rport[0]   ? rport   : "*",
        fw_profile_name(profile),
        appname[0] ? appname : "-"
    );
}

static void fw_print_header(void) {
    internal_printf("%-35s %-6s %-4s %-6s %-5s %-10s %-10s %-10s %s\n",
        "Name", "Action", "Dir", "Active",
        "Proto", "LPort", "RPort", "Profile", "App");
    internal_printf(
        "----------------------------------- "
        "------ ---- ------ ----- "
        "---------- ---------- ---------- "
        "-------------------\n");
}

// -----------------------------------------------------------------------
// Open the firewall rules registry key (local or remote)
// -----------------------------------------------------------------------
static LONG fw_open_key(const char *hostname, REGSAM access,
                         HKEY *hKeyOut, HKEY *hRemoteOut) {
    *hKeyOut    = NULL;
    *hRemoteOut = NULL;
    LONG rc;

    if (hostname && hostname[0]) {
        char unc[256] = {0};
        unc[0] = '\\'; unc[1] = '\\';
        fw_strncpy(unc + 2, hostname, sizeof(unc) - 2);
        rc = ADVAPI32$RegConnectRegistryA(unc, HKEY_LOCAL_MACHINE, hRemoteOut);
        if (rc != ERROR_SUCCESS) return rc;
        rc = ADVAPI32$RegOpenKeyExA(*hRemoteOut, FW_REG_PATH, 0, access, hKeyOut);
    } else {
        rc = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, FW_REG_PATH, 0, access, hKeyOut);
    }
    return rc;
}

static void fw_close_key(HKEY hKey, HKEY hRemote) {
    if (hKey)    ADVAPI32$RegCloseKey(hKey);
    if (hRemote) ADVAPI32$RegCloseKey(hRemote);
}
