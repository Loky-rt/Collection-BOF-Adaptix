var metadata = {
    name: "FW-BOF",
    description: "Windows Firewall management via registry BOFs"
};

// -----------------------------------------------------------------------
// fw_list — List firewall rules with optional filters
// -----------------------------------------------------------------------
var cmd_fw_list = ax.create_command(
    "fw_list",
    "List Windows Firewall rules from the registry. All filters are optional and combinable.",
    "fw_list | fw_list -d In | fw_list -a Block | fw_list -n Remote | fw_list -d In -a Allow -c 192.168.1.10"
);
cmd_fw_list.addArgFlagString("-c", "host",   "Remote hostname (skip = local)",          "");
cmd_fw_list.addArgFlagString("-d", "dir",    "Direction filter: In | Out",              "");
cmd_fw_list.addArgFlagString("-a", "action", "Action filter: Allow | Block",            "");
cmd_fw_list.addArgFlagString("-s", "active", "State filter: TRUE | FALSE",              "");
cmd_fw_list.addArgFlagString("-n", "name",   "Name filter (substring, case-insensitive)", "");
cmd_fw_list.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var host   = parsed_json["host"]   || "";
    var dir    = parsed_json["dir"]    || "";
    var action = parsed_json["action"] || "";
    var active = parsed_json["active"] || "";
    var name   = parsed_json["name"]   || "";

    var bof_params = ax.bof_pack("cstr,cstr,cstr,cstr,cstr", [host, dir, action, active, name]);
    var bof_path   = ax.script_dir() + "_bin/fw_list." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline,
        `execute bof "${bof_path}" ${bof_params}`,
        "Task: Firewall LIST");
});

// -----------------------------------------------------------------------
// fw_add — Add a new firewall rule
// -----------------------------------------------------------------------
var cmd_fw_add = ax.create_command(
    "fw_add",
    "Add a Windows Firewall rule via the registry.",
    "fw_add -n WindowsUpdate -d In -p 6 -l 4444 | fw_add -n BlockDNS -a Block -d Out -p 17 -r 53"
);
cmd_fw_add.addArgFlagString("-c", "host",     "Remote hostname (skip = local)",                    "");
cmd_fw_add.addArgFlagString("-n", "name",     "Rule display name (required)",                      "");
cmd_fw_add.addArgFlagString("-a", "action",   "Action: Allow | Block",                             "Allow");
cmd_fw_add.addArgFlagString("-d", "dir",      "Direction: In | Out",                               "In");
cmd_fw_add.addArgFlagString("-p", "proto",    "Protocol: 6=TCP | 17=UDP | 1=ICMP | 256=Any",       "256");
cmd_fw_add.addArgFlagString("-l", "lport",    "Local port or range (e.g. 4444 or 4400-4500)",      "");
cmd_fw_add.addArgFlagString("-r", "rport",    "Remote port or range",                              "");
cmd_fw_add.addArgFlagString("-x", "app",      "Application path",                                  "");
cmd_fw_add.addArgFlagString("-f", "profile",  "Profile: 1=Domain | 2=Private | 4=Public | 2147483647=Any", "2147483647");
cmd_fw_add.addArgFlagString("-e", "desc",     "Description",                                       "");
cmd_fw_add.addArgFlagString("-s", "active",   "Active: 1=enabled | 0=disabled",                   "1");
cmd_fw_add.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var host    = parsed_json["host"]    || "";
    var name    = parsed_json["name"]    || "";
    var action  = parsed_json["action"]  || "Allow";
    var dir     = parsed_json["dir"]     || "In";
    var proto   = parsed_json["proto"]   || "256";
    var lport   = parsed_json["lport"]   || "";
    var rport   = parsed_json["rport"]   || "";
    var app     = parsed_json["app"]     || "";
    var profile = parsed_json["profile"] || "2147483647";
    var desc    = parsed_json["desc"]    || "";
    var active  = parseInt(parsed_json["active"] || "1");

    if (!name) {
        ax.console_message(id, "fw_add: -n <name> is required", "error");
        return;
    }

    var bof_params = ax.bof_pack("cstr,cstr,cstr,cstr,cstr,cstr,cstr,cstr,cstr,cstr,int",
        [host, name, action, dir, proto, lport, rport, app, profile, desc, active]);
    var bof_path = ax.script_dir() + "_bin/fw_add." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline,
        `execute bof "${bof_path}" ${bof_params}`,
        "Task: Firewall ADD [" + name + "]");
});

// -----------------------------------------------------------------------
// fw_delete — Delete a firewall rule by name
// -----------------------------------------------------------------------
var cmd_fw_delete = ax.create_command(
    "fw_delete",
    "Delete a Windows Firewall rule from the registry by its display name.",
    "fw_delete -n WindowsUpdate | fw_delete -n BackdoorRule -c 10.10.1.5"
);
cmd_fw_delete.addArgFlagString("-c", "host", "Remote hostname (skip = local)", "");
cmd_fw_delete.addArgFlagString("-n", "name", "Rule display name (required)",   "");
cmd_fw_delete.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var host = parsed_json["host"] || "";
    var name = parsed_json["name"] || "";

    if (!name) {
        ax.console_message(id, "fw_delete: -n <name> is required", "error");
        return;
    }

    var bof_params = ax.bof_pack("cstr,cstr", [host, name]);
    var bof_path   = ax.script_dir() + "_bin/fw_delete." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline,
        `execute bof "${bof_path}" ${bof_params}`,
        "Task: Firewall DELETE [" + name + "]");
});

// -----------------------------------------------------------------------
// fw_find — Search rules by pattern
// -----------------------------------------------------------------------
var cmd_fw_find = ax.create_command(
    "fw_find",
    "Search Windows Firewall rules by pattern. Case-insensitive substring match.",
    "fw_find -s Remote Desktop | fw_find -s svchost -f app | fw_find -s 445 -f port | fw_find -s chrome -f any"
);
cmd_fw_find.addArgFlagString("-c", "host",    "Remote hostname (skip = local)",                    "");
cmd_fw_find.addArgFlagString("-s", "pattern", "Search pattern (required)",                         "");
cmd_fw_find.addArgFlagString("-f", "field",   "Search field: name | app | port | any",             "name");
cmd_fw_find.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var host    = parsed_json["host"]    || "";
    var pattern = parsed_json["pattern"] || "";
    var field   = parsed_json["field"]   || "name";

    if (!pattern) {
        ax.console_message(id, "fw_find: -s <pattern> is required", "error");
        return;
    }

    var field_i = 0;
    if (field === "app")  field_i = 1;
    if (field === "port") field_i = 2;
    if (field === "any")  field_i = 3;

    var bof_params = ax.bof_pack("cstr,cstr,int", [host, pattern, field_i]);
    var bof_path   = ax.script_dir() + "_bin/fw_find." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline,
        `execute bof "${bof_path}" ${bof_params}`,
        "Task: Firewall FIND [" + pattern + "]");
});

// -----------------------------------------------------------------------
// fw_toggle — Enable or disable a rule without deleting it
// -----------------------------------------------------------------------
var cmd_fw_toggle = ax.create_command(
    "fw_toggle",
    "Enable or disable a Windows Firewall rule without deleting it. Flips the Active field in the registry.",
    "fw_toggle -n WindowsDefender -s disable | fw_toggle -n WindowsDefender -s enable -c 10.0.0.5"
);
cmd_fw_toggle.addArgFlagString("-c", "host",  "Remote hostname (skip = local)",        "");
cmd_fw_toggle.addArgFlagString("-n", "name",  "Rule display name (required)",          "");
cmd_fw_toggle.addArgFlagString("-s", "state", "State: enable | disable",               "enable");
cmd_fw_toggle.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var host  = parsed_json["host"]  || "";
    var name  = parsed_json["name"]  || "";
    var state = parsed_json["state"] || "enable";

    if (!name) {
        ax.console_message(id, "fw_toggle: -n <name> is required", "error");
        return;
    }

    var enable_i = (state === "disable") ? 0 : 1;

    var bof_params = ax.bof_pack("cstr,cstr,int", [host, name, enable_i]);
    var bof_path   = ax.script_dir() + "_bin/fw_toggle." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline,
        `execute bof "${bof_path}" ${bof_params}`,
        "Task: Firewall TOGGLE " + state + " [" + name + "]");
});

// -----------------------------------------------------------------------
// Register all commands as a group
// -----------------------------------------------------------------------
var group_fw = ax.create_commands_group("FW-BOF",
    [cmd_fw_list, cmd_fw_add, cmd_fw_delete, cmd_fw_find, cmd_fw_toggle]);
ax.register_commands_group(group_fw, ["beacon", "gopher", "kharon", "NoNameAx"], ["windows"], []);
