#include <windows.h>
void printoutput(BOOL done);
#define DYNAMIC_LIB_COUNT 1
#include "../_include/base.c"

// -----------------------------------------------------------------------
// ADVAPI32 imports — Registry
// -----------------------------------------------------------------------
DECLSPEC_IMPORT LONG  WINAPI ADVAPI32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG  WINAPI ADVAPI32$RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG  WINAPI ADVAPI32$RegQueryInfoKeyA(HKEY, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LONG  WINAPI ADVAPI32$RegEnumKeyExA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LONG  WINAPI ADVAPI32$RegEnumValueA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG  WINAPI ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT LONG  WINAPI ADVAPI32$RegCreateKeyExA(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
DECLSPEC_IMPORT LONG  WINAPI ADVAPI32$RegSetValueExA(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
DECLSPEC_IMPORT LONG  WINAPI ADVAPI32$RegDeleteValueA(HKEY, LPCSTR);
DECLSPEC_IMPORT LONG  WINAPI ADVAPI32$RegDeleteTreeA(HKEY, LPCSTR);
DECLSPEC_IMPORT LONG  WINAPI ADVAPI32$RegConnectRegistryA(LPCSTR, HKEY, PHKEY);
DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$AllocateAndInitializeSid(PSID_IDENTIFIER_AUTHORITY, BYTE, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, PSID*);
DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$CheckTokenMembership(HANDLE, PSID, PBOOL);
DECLSPEC_IMPORT PVOID WINAPI ADVAPI32$FreeSid(PSID);

// -----------------------------------------------------------------------
// Helpers de string (sin depender de MSVCRT)
// -----------------------------------------------------------------------
static int my_strcmp(const char* a, const char* b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static int my_strncmpi(const char* a, const char* b, int n) {
    int i = 0;
    while (i < n && *a && *b) {
        char ca = (*a >= 'A' && *a <= 'Z') ? (*a + 32) : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? (*b + 32) : *b;
        if (ca != cb) return (unsigned char)ca - (unsigned char)cb;
        a++; b++; i++;
    }
    return (i == n) ? 0 : (unsigned char)*a - (unsigned char)*b;
}

static int my_strcmpi(const char* a, const char* b) {
    while (*a && *b) {
        char ca = (*a >= 'A' && *a <= 'Z') ? (*a + 32) : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? (*b + 32) : *b;
        if (ca != cb) return (unsigned char)ca - (unsigned char)cb;
        a++; b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

// NOTE: pointer arithmetic implementation intentional — GCC -Os recognizes the
// indexed loop (s[n]) as strlen() and emits an external symbol that BOF loaders
// cannot resolve. The pointer form (e - s) avoids that pattern match.
static __attribute__((noinline)) int my_strlen(const char* s) {
    const char* e = s;
    while (*e) e++;
    return (int)(e - s);
}

static void my_strcpy(char* dst, const char* src) {
    while ((*dst++ = *src++));
}

// Convierte hex string "AABBCC" a bytes
static int hex_to_bytes(const char* hex, BYTE* out, int maxOut) {
    int len = my_strlen(hex);
    int n = 0;
    for (int i = 0; i + 1 < len && n < maxOut; i += 2) {
        char hi = hex[i],   lo = hex[i+1];
        int  h  = (hi >= '0' && hi <= '9') ? hi - '0' :
                  (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10 :
                  (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : 0;
        int  l  = (lo >= '0' && lo <= '9') ? lo - '0' :
                  (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10 :
                  (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : 0;
        out[n++] = (BYTE)((h << 4) | l);
    }
    return n;
}

// -----------------------------------------------------------------------
// Resolucion de hive
// -----------------------------------------------------------------------
static HKEY resolve_hive(const char* hive) {
    if (!my_strcmpi(hive, "HKLM") || !my_strcmpi(hive, "HKEY_LOCAL_MACHINE"))
        return HKEY_LOCAL_MACHINE;
    if (!my_strcmpi(hive, "HKCU") || !my_strcmpi(hive, "HKEY_CURRENT_USER"))
        return HKEY_CURRENT_USER;
    if (!my_strcmpi(hive, "HKCR") || !my_strcmpi(hive, "HKEY_CLASSES_ROOT"))
        return HKEY_CLASSES_ROOT;
    if (!my_strcmpi(hive, "HKU")  || !my_strcmpi(hive, "HKEY_USERS"))
        return HKEY_USERS;
    if (!my_strcmpi(hive, "HKCC") || !my_strcmpi(hive, "HKEY_CURRENT_CONFIG"))
        return HKEY_CURRENT_CONFIG;
    return NULL;
}

// -----------------------------------------------------------------------
// Verificacion de privilegios por hive
// -----------------------------------------------------------------------
static BOOL hive_requires_admin(HKEY hive) {
    return (hive == HKEY_LOCAL_MACHINE  ||
            hive == HKEY_CLASSES_ROOT   ||
            hive == HKEY_USERS          ||
            hive == HKEY_CURRENT_CONFIG);
}

static BOOL is_admin(void) {
    BOOL result = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID adminSid = NULL;
    if (ADVAPI32$AllocateAndInitializeSid(&ntAuth, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminSid)) {
        ADVAPI32$CheckTokenMembership(NULL, adminSid, &result);
        ADVAPI32$FreeSid(adminSid);
    }
    return result;
}

// -----------------------------------------------------------------------
// Resolucion de tipo REG
// -----------------------------------------------------------------------
static DWORD resolve_type(const char* t) {
    if (!my_strcmpi(t, "REG_SZ"))        return REG_SZ;
    if (!my_strcmpi(t, "REG_DWORD"))     return REG_DWORD;
    if (!my_strcmpi(t, "REG_QWORD"))     return REG_QWORD;
    if (!my_strcmpi(t, "REG_BINARY"))    return REG_BINARY;
    if (!my_strcmpi(t, "REG_EXPAND_SZ")) return REG_EXPAND_SZ;
    if (!my_strcmpi(t, "REG_MULTI_SZ"))  return REG_MULTI_SZ;
    return REG_NONE;
}

static const char* type_name(DWORD t) {
    switch (t) {
        case REG_SZ:        return "REG_SZ";
        case REG_DWORD:     return "REG_DWORD";
        case REG_QWORD:     return "REG_QWORD";
        case REG_BINARY:    return "REG_BINARY";
        case REG_EXPAND_SZ: return "REG_EXPAND_SZ";
        case REG_MULTI_SZ:  return "REG_MULTI_SZ";
        case REG_NONE:      return "REG_NONE";
        default:            return "UNKNOWN";
    }
}

// -----------------------------------------------------------------------
// Impresion de valor
// -----------------------------------------------------------------------
static void print_value(const char* name, DWORD type, BYTE* data, DWORD dataLen) {
    internal_printf("    %-30s  %-15s  ",
        name[0] ? name : "(Default)", type_name(type));

    switch (type) {
        case REG_SZ:
        case REG_EXPAND_SZ: {
            char* str = (char*)data;
            DWORD printLen = dataLen;
            if (printLen > 0 && str[printLen - 1] == '\0') printLen--;
            str[printLen] = '\0'; // safe: buffer alloc'd con +2
            internal_printf("%s\n", str);
            break;
        }
        case REG_MULTI_SZ: {
            // Strings separados por \0, termina en \0\0
            char* p = (char*)data;
            BOOL first = TRUE;
            while (*p && (DWORD)(p - (char*)data) < dataLen) {
                if (!first) internal_printf("|");
                internal_printf("%s", p);
                p += my_strlen(p) + 1;
                first = FALSE;
            }
            internal_printf("\n");
            break;
        }
        case REG_DWORD:
            if (dataLen >= 4) {
                DWORD v; MSVCRT$memcpy(&v, data, 4);
                internal_printf("0x%08lx (%lu)\n", (unsigned long)v, (unsigned long)v);
            }
            break;
        case REG_QWORD:
            if (dataLen >= 8) {
                ULONGLONG v; MSVCRT$memcpy(&v, data, 8);
                internal_printf("0x%016llx\n", v);
            }
            break;
        case REG_BINARY:
            for (DWORD i = 0; i < dataLen; i++)
                internal_printf("%02x ", data[i]);
            internal_printf("\n");
            break;
        default:
            internal_printf("<binary %lu bytes>\n", (unsigned long)dataLen);
            break;
    }
}

// -----------------------------------------------------------------------
// reg query
// -----------------------------------------------------------------------
static void cmd_query(HKEY hRoot, const char* key, const char* value,
                      const char* machine) {
    HKEY hRemote = hRoot;

    if (machine && machine[0]) {
        char unc[256] = {0};
        unc[0] = '\\'; unc[1] = '\\';
        my_strcpy(unc + 2, machine);
        LONG rc = ADVAPI32$RegConnectRegistryA(unc, hRoot, &hRemote);
        if (rc != ERROR_SUCCESS) {
            internal_printf("[-] RegConnectRegistry failed for %s (error %ld)\n",
                machine, (long)rc);
            return;
        }
    }

    HKEY hKey = NULL;
    LONG rc = ADVAPI32$RegOpenKeyExA(hRemote, key, 0, KEY_READ, &hKey);
    if (rc != ERROR_SUCCESS) {
        internal_printf("[-] Cannot open key '%s' (error %ld)\n", key, (long)rc);
        if (machine && machine[0]) ADVAPI32$RegCloseKey(hRemote);
        return;
    }

    internal_printf("\n[*] %s\\%s\n\n", key, value ? value : "");

    if (value && value[0]) {
        DWORD type = 0, dataLen = 0;
        ADVAPI32$RegQueryValueExA(hKey, value, NULL, &type, NULL, &dataLen);
        BYTE* data = (BYTE*)intAlloc(dataLen + 2);
        if (data) {
            rc = ADVAPI32$RegQueryValueExA(hKey, value, NULL, &type, data, &dataLen);
            if (rc == ERROR_SUCCESS)
                print_value(value, type, data, dataLen);
            else
                internal_printf("[-] Value '%s' not found (error %ld)\n", value, (long)rc);
            intFree(data);
        }
    } else {
        DWORD numValues = 0, maxValueName = 0, maxValueData = 0;
        DWORD numSubKeys = 0, maxSubKeyLen = 0;
        ADVAPI32$RegQueryInfoKeyA(hKey, NULL, NULL, NULL,
            &numSubKeys, &maxSubKeyLen, NULL,
            &numValues, &maxValueName, &maxValueData, NULL, NULL);

        if (numSubKeys > 0) {
            internal_printf("  Subkeys (%lu):\n", (unsigned long)numSubKeys);
            char* skName = (char*)intAlloc(maxSubKeyLen + 2);
            if (skName) {
                for (DWORD i = 0; i < numSubKeys; i++) {
                    DWORD skLen = maxSubKeyLen + 1;
                    rc = ADVAPI32$RegEnumKeyExA(hKey, i, skName, &skLen,
                                                NULL, NULL, NULL, NULL);
                    if (rc == ERROR_SUCCESS)
                        internal_printf("    [+] %s\n", skName);
                }
                intFree(skName);
            }
            internal_printf("\n");
        }

        if (numValues > 0) {
            internal_printf("  %-30s  %-15s  %s\n", "Name", "Type", "Data");
            internal_printf("  %-30s  %-15s  %s\n",
                "------------------------------", "---------------", "----");

            char* vName = (char*)intAlloc(maxValueName + 2);
            BYTE* vData = (BYTE*)intAlloc(maxValueData + 2);
            if (vName && vData) {
                for (DWORD i = 0; i < numValues; i++) {
                    DWORD vnLen = maxValueName + 1;
                    DWORD vdLen = maxValueData + 2;
                    DWORD vType = 0;
                    MSVCRT$memset(vName, 0, maxValueName + 2);
                    MSVCRT$memset(vData, 0, maxValueData + 2);
                    rc = ADVAPI32$RegEnumValueA(hKey, i, vName, &vnLen,
                                               NULL, &vType, vData, &vdLen);
                    if (rc == ERROR_SUCCESS)
                        print_value(vName, vType, vData, vdLen);
                }
            }
            if (vName) intFree(vName);
            if (vData) intFree(vData);
        }

        if (numSubKeys == 0 && numValues == 0)
            internal_printf("  (empty key)\n");
    }

    ADVAPI32$RegCloseKey(hKey);
    if (machine && machine[0]) ADVAPI32$RegCloseKey(hRemote);
}

// -----------------------------------------------------------------------
// reg add
// -----------------------------------------------------------------------
static void cmd_add(HKEY hRoot, const char* key, const char* value,
                    const char* typeStr, const char* dataStr,
                    const char* machine) {
    if (hive_requires_admin(hRoot) && !is_admin()) {
        internal_printf("[-] Insufficient privileges: writing to this hive requires Administrator.\n");
        return;
    }

    HKEY hRemote = hRoot;
    if (machine && machine[0]) {
        char unc[256] = {0};
        unc[0] = '\\'; unc[1] = '\\';
        my_strcpy(unc + 2, machine);
        LONG rc = ADVAPI32$RegConnectRegistryA(unc, hRoot, &hRemote);
        if (rc != ERROR_SUCCESS) {
            internal_printf("[-] RegConnectRegistry failed for %s (error %ld)\n",
                machine, (long)rc);
            return;
        }
    }

    HKEY hKey = NULL;
    DWORD disp = 0;
    LONG rc = ADVAPI32$RegCreateKeyExA(hRemote, key, 0, NULL,
                                        REG_OPTION_NON_VOLATILE,
                                        KEY_WRITE, NULL, &hKey, &disp);
    if (rc != ERROR_SUCCESS) {
        internal_printf("[-] Cannot create/open key '%s' (error %ld)\n", key, (long)rc);
        if (machine && machine[0]) ADVAPI32$RegCloseKey(hRemote);
        return;
    }

    DWORD type = resolve_type(typeStr);
    if (type == REG_NONE) {
        internal_printf("[-] Unknown type '%s'. Supported: REG_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_EXPAND_SZ, REG_MULTI_SZ\n", typeStr);
        ADVAPI32$RegCloseKey(hKey);
        if (machine && machine[0]) ADVAPI32$RegCloseKey(hRemote);
        return;
    }

    #define REG_BUF_SIZE 4096
    BYTE* buf = (BYTE*)intAlloc(REG_BUF_SIZE);
    if (!buf) {
        internal_printf("[-] Memory allocation failed.\n");
        ADVAPI32$RegCloseKey(hKey);
        if (machine && machine[0]) ADVAPI32$RegCloseKey(hRemote);
        return;
    }
    DWORD bufLen = 0;

    switch (type) {
        case REG_SZ:
        case REG_EXPAND_SZ: {
            int slen = my_strlen(dataStr);
            MSVCRT$memcpy(buf, dataStr, slen + 1);
            bufLen = slen + 1;
            break;
        }
        case REG_MULTI_SZ: {
            const char* p = dataStr;
            DWORD pos = 0;
            while (*p) {
                while (*p && *p != '|' && pos < REG_BUF_SIZE - 2) buf[pos++] = *p++;
                buf[pos++] = '\0';
                if (*p == '|') p++;
            }
            buf[pos++] = '\0';
            bufLen = pos;
            break;
        }
        case REG_DWORD: {
            DWORD v = 0;
            const char* p = dataStr;
            if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
                p += 2;
                while (*p) {
                    int d = (*p >= '0' && *p <= '9') ? *p - '0' :
                            (*p >= 'a' && *p <= 'f') ? *p - 'a' + 10 :
                            (*p >= 'A' && *p <= 'F') ? *p - 'A' + 10 : 0;
                    v = v * 16 + d; p++;
                }
            } else {
                while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
            }
            MSVCRT$memcpy(buf, &v, 4);
            bufLen = 4;
            break;
        }
        case REG_QWORD: {
            ULONGLONG v = 0;
            const char* p = dataStr;
            if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
                p += 2;
                while (*p) {
                    int d = (*p >= '0' && *p <= '9') ? *p - '0' :
                            (*p >= 'a' && *p <= 'f') ? *p - 'a' + 10 :
                            (*p >= 'A' && *p <= 'F') ? *p - 'A' + 10 : 0;
                    v = v * 16 + d; p++;
                }
            } else {
                while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
            }
            MSVCRT$memcpy(buf, &v, 8);
            bufLen = 8;
            break;
        }
        case REG_BINARY:
            bufLen = hex_to_bytes(dataStr, buf, REG_BUF_SIZE);
            break;
    }

    rc = ADVAPI32$RegSetValueExA(hKey, value, 0, type, buf, bufLen);
    intFree(buf);
    if (rc == ERROR_SUCCESS) {
        internal_printf("[+] Value '%s' written successfully to '%s'\n", value, key);
        internal_printf("    Type : %s\n", type_name(type));
        internal_printf("    Data : %s\n", dataStr);
    } else {
        internal_printf("[-] RegSetValueEx failed (error %ld)\n", (long)rc);
    }

    ADVAPI32$RegCloseKey(hKey);
    if (machine && machine[0]) ADVAPI32$RegCloseKey(hRemote);
}

// -----------------------------------------------------------------------
// reg delete
// -----------------------------------------------------------------------
static void cmd_delete(HKEY hRoot, const char* key, const char* value,
                       const char* machine) {
    if (hive_requires_admin(hRoot) && !is_admin()) {
        internal_printf("[-] Insufficient privileges: deleting from this hive requires Administrator.\n");
        return;
    }

    HKEY hRemote = hRoot;
    if (machine && machine[0]) {
        char unc[256] = {0};
        unc[0] = '\\'; unc[1] = '\\';
        my_strcpy(unc + 2, machine);
        LONG rc = ADVAPI32$RegConnectRegistryA(unc, hRoot, &hRemote);
        if (rc != ERROR_SUCCESS) {
            internal_printf("[-] RegConnectRegistry failed for %s (error %ld)\n",
                machine, (long)rc);
            return;
        }
    }

    LONG rc;
    if (value && value[0]) {
        HKEY hKey = NULL;
        rc = ADVAPI32$RegOpenKeyExA(hRemote, key, 0, KEY_WRITE, &hKey);
        if (rc != ERROR_SUCCESS) {
            internal_printf("[-] Cannot open key '%s' (error %ld)\n", key, (long)rc);
        } else {
            rc = ADVAPI32$RegDeleteValueA(hKey, value);
            if (rc == ERROR_SUCCESS)
                internal_printf("[+] Value '%s' deleted from '%s'\n", value, key);
            else
                internal_printf("[-] RegDeleteValue failed (error %ld)\n", (long)rc);
            ADVAPI32$RegCloseKey(hKey);
        }
    } else {
        rc = ADVAPI32$RegDeleteTreeA(hRemote, key);
        if (rc == ERROR_SUCCESS)
            internal_printf("[+] Key '%s' deleted successfully\n", key);
        else
            internal_printf("[-] RegDeleteTree failed (error %ld)\n", (long)rc);
    }

    if (machine && machine[0]) ADVAPI32$RegCloseKey(hRemote);
}

// -----------------------------------------------------------------------
// Tokenizer simple
// -----------------------------------------------------------------------
#define MAX_TOKENS 8
#define MAX_TOKEN_LEN 1024

static int tokenize(char* input, char tokens[MAX_TOKENS][MAX_TOKEN_LEN]) {
    int count = 0;
    char* p = input;
    while (*p && count < MAX_TOKENS) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;

        int i = 0;
        if (*p == '"') {
            p++;
            while (*p && *p != '"' && i < MAX_TOKEN_LEN - 1)
                tokens[count][i++] = *p++;
            if (*p == '"') p++;
        } else {
            while (*p && *p != ' ' && *p != '\t' && i < MAX_TOKEN_LEN - 1)
                tokens[count][i++] = *p++;
        }
        tokens[count][i] = '\0';
        count++;
    }
    return count;
}

static char* find_machine(char tokens[MAX_TOKENS][MAX_TOKEN_LEN], int count) {
    static char machine[256];
    machine[0] = '\0';
    for (int i = 0; i < count; i++) {
        if (my_strncmpi(tokens[i], "/machine:", 9) == 0) {
            int k = 0;
            char* v = tokens[i] + 9;
            while (*v && k < 255) machine[k++] = *v++;
            machine[k] = '\0';
            return machine;
        }
    }
    return machine;
}

// -----------------------------------------------------------------------
// Entry point
// -----------------------------------------------------------------------
void go(char* args, int len) {
    bofstart();

    datap parser;
    BeaconDataParse(&parser, args, len);

    int param_len = 0;
    char* params = BeaconDataExtract(&parser, &param_len);

    if (!params || param_len <= 0) {
        internal_printf("[-] No arguments provided.\n");
        internal_printf("    reg query  <hive> <key> [value] [/machine:HOST]\n");
        internal_printf("    reg add    <hive> <key> <value> <type> <data> [/machine:HOST]\n");
        internal_printf("    reg delete <hive> <key> [value] [/machine:HOST]\n");
        printoutput(TRUE);
        bofstop();
        return;
    }

    char (*tokens)[MAX_TOKEN_LEN] = (char (*)[MAX_TOKEN_LEN])intAlloc(MAX_TOKENS * MAX_TOKEN_LEN);
    if (!tokens) {
        internal_printf("[-] Memory allocation failed.\n");
        printoutput(TRUE);
        bofstop();
        return;
    }
    MSVCRT$memset(tokens, 0, MAX_TOKENS * MAX_TOKEN_LEN);
    int count = tokenize(params, tokens);

    if (count < 3) {
        internal_printf("[-] Too few arguments. Minimum: <subcommand> <hive> <key>\n");
        intFree(tokens);
        printoutput(TRUE);
        bofstop();
        return;
    }

    char* command = tokens[0];
    char* hiveStr = tokens[1];
    char* key     = tokens[2];
    char* value   = (count > 3) ? tokens[3] : "";
    char* typeStr = (count > 4) ? tokens[4] : "";
    char* data    = (count > 5) ? tokens[5] : "";
    char* machine = find_machine(tokens, count);

    HKEY hRoot = resolve_hive(hiveStr);
    if (!hRoot) {
        internal_printf("[-] Unknown hive '%s'. Use: HKLM, HKCU, HKCR, HKU, HKCC\n", hiveStr);
        intFree(tokens);
        printoutput(TRUE);
        bofstop();
        return;
    }

    if (!my_strcmpi(command, "reg_query")) {
        char* qvalue = (value[0] && value[0] != '/') ? value : "";
        cmd_query(hRoot, key, qvalue, machine);
    } else if (!my_strcmpi(command, "reg_add")) {
        if (!value[0] || !typeStr[0] || !data[0]) {
            internal_printf("[-] 'reg_add' requires: <hive> <key> <value> <type> <data>\n");
        } else {
            cmd_add(hRoot, key, value, typeStr, data, machine);
        }
    } else if (!my_strcmpi(command, "reg_delete")) {
        char* dvalue = (value[0] && value[0] != '/') ? value : "";
        cmd_delete(hRoot, key, dvalue, machine);
    } else {
        internal_printf("[-] Unknown subcommand '%s'. Use: reg_query, reg_add, reg_delete\n", command);
    }

    intFree(tokens);
    printoutput(TRUE);
    bofstop();
}
