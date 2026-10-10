var metadata = {
    name: "SvcMgr-BOF",
    description: "Windows service management (list/query/create/delete/start/stop/configure) local and remote via SCM."
};

// ── svc_list ─────────────────────────────────────────────────
var cmd_svc_list = ax.create_command(
    "svc_list",
    "List all services (local or remote).",
    "svc_list | svc_list -c 192.168.1.10 | svc_list -f driver");
cmd_svc_list.addArgFlagString("-c", "computer", "Remote computer (skip = localhost)", "localhost");
cmd_svc_list.addArgFlagString("-f", "filter",   "Filter: all | win32 | driver", "all");
cmd_svc_list.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var computer   = parsed_json["computer"] || "localhost";
    var filter     = parsed_json["filter"]   || "all";
    var bof_path   = ax.script_dir() + "_bin/svcmgr." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("cstr,cstr,cstr", ["list", computer, filter]);
    ax.execute_alias(id, cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: svc_list on " + computer, null);
});

// ── svc_query ────────────────────────────────────────────────
var cmd_svc_query = ax.create_command(
    "svc_query",
    "Check the status and configuration of a service.",
    "svc_query -n WinDefend | svc_query -n Spooler -c 192.168.1.10");
cmd_svc_query.addArgFlagString("-n", "svcname",  "Service name");
cmd_svc_query.addArgFlagString("-c", "computer", "Remote machine (skip = localhost)", "localhost");
cmd_svc_query.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var svcname    = parsed_json["svcname"]  || "";
    var computer   = parsed_json["computer"] || "localhost";
    if (!svcname) { ax.console_message(id, "missing -n <svcname>", "error"); return; }

    var bof_path   = ax.script_dir() + "_bin/svcmgr." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("cstr,cstr,cstr", ["query", computer, svcname]);
    ax.execute_alias(id, cmdline,
        `execute bof "${bof_path}" "${bof_params}"`,
        "Task: svc_query [" + svcname + "] on " + computer, null);
});

// ── svc_create ───────────────────────────────────────────────
var cmd_svc_create = ax.create_command(
    "svc_create",
    "Create a new service (Win32 or kernel driver).",
    "svc_create -n MySvc -p C:\\\\path\\\\svc.exe -t win32 -s auto | svc_create -n MyDrv -p C:\\\\path\\\\drv.sys -t driver -s demand");
cmd_svc_create.addArgFlagString("-n", "svcname",   "Service internal name");
cmd_svc_create.addArgFlagString("-p", "binpath",   "Path to the executable or .sys file");
cmd_svc_create.addArgFlagString("-d", "dispname",  "Display name (optional)", "");
cmd_svc_create.addArgFlagString("-t", "svctype",   "Type: win32 | driver", "win32");
cmd_svc_create.addArgFlagString("-s", "starttype", "Start: auto | demand | disabled | boot | system", "demand");
cmd_svc_create.addArgFlagString("-c", "computer",  "Remote machine (skip = localhost)", "localhost");
cmd_svc_create.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var svcname    = parsed_json["svcname"]   || "";
    var binpath    = parsed_json["binpath"]   || "";
    var dispname   = parsed_json["dispname"]  || "";
    var svctype    = parsed_json["svctype"]   || "win32";
    var starttype  = parsed_json["starttype"] || "demand";
    var computer   = parsed_json["computer"]  || "localhost";
    if (!svcname) { ax.console_message(id, "missing -n <svcname>", "error"); return; }
    if (!binpath) { ax.console_message(id, "missing -p <binpath>", "error"); return; }
    var bof_path   = ax.script_dir() + "_bin/svcmgr." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("cstr,cstr,cstr,cstr,cstr,cstr,cstr",
        ["create", computer, svcname, dispname, binpath, svctype, starttype]);
    ax.execute_alias(id, cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: svc_create [" + svcname + "] on " + computer, null);
});

// ── svc_delete ───────────────────────────────────────────────
var cmd_svc_delete = ax.create_command(
    "svc_delete",
    "Remove a service (stops it first if running).",
    "svc_delete -n MySvc | svc_delete -n MySvc -c 192.168.1.10");
cmd_svc_delete.addArgFlagString("-n", "svcname",  "Service name");
cmd_svc_delete.addArgFlagString("-c", "computer", "Remote machine (skip = localhost)", "localhost");
cmd_svc_delete.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var svcname    = parsed_json["svcname"]  || "";
    var computer   = parsed_json["computer"] || "localhost";
    if (!svcname) { ax.console_message(id, "missing -n <svcname>", "error"); return; }
    var bof_path   = ax.script_dir() + "_bin/svcmgr." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("cstr,cstr,cstr", ["delete", computer, svcname]);
    ax.execute_alias(id, cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: svc_delete [" + svcname + "] on " + computer, null);
});

// ── svc_start ────────────────────────────────────────────────
var cmd_svc_start = ax.create_command(
    "svc_start",
    "Start a service and wait for RUNNING confirmation.",
    "svc_start -n Spooler | svc_start -n MySvc -c 192.168.1.10");
cmd_svc_start.addArgFlagString("-n", "svcname",  "Service name");
cmd_svc_start.addArgFlagString("-c", "computer", "Remote machine (skip = localhost)", "localhost");
cmd_svc_start.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var svcname    = parsed_json["svcname"]  || "";
    var computer   = parsed_json["computer"] || "localhost";
    if (!svcname) { ax.console_message(id, "missing -n <svcname>", "error"); return; }
    var bof_path   = ax.script_dir() + "_bin/svcmgr." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("cstr,cstr,cstr", ["start", computer, svcname]);
    ax.execute_alias(id, cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: svc_start [" + svcname + "] on " + computer, null);
});

// ── svc_stop ─────────────────────────────────────────────────
var cmd_svc_stop = ax.create_command(
    "svc_stop",
    "Stop a service and wait for STOPPED confirmation.",
    "svc_stop -n Spooler | svc_stop -n MySvc -c 192.168.1.10");
cmd_svc_stop.addArgFlagString("-n", "svcname",  "Service name");
cmd_svc_stop.addArgFlagString("-c", "computer", "Remote machine (skip = localhost)", "localhost");
cmd_svc_stop.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var svcname    = parsed_json["svcname"]  || "";
    var computer   = parsed_json["computer"] || "localhost";
    if (!svcname) { ax.console_message(id, "missing -n <svcname>", "error"); return; }
    var bof_path   = ax.script_dir() + "_bin/svcmgr." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("cstr,cstr,cstr", ["stop", computer, svcname]);
    ax.execute_alias(id, cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: svc_stop [" + svcname + "] on " + computer, null);
});


// ── svc_configure ─────────────────────────────────────────────
var cmd_svc_configure = ax.create_command(
    "svc_configure",
    "Reconfigure an existing service (start type, binary path or display name).",
    "svc_configure -n MSSQLSERVER -s demand | svc_configure -n Spooler -s disabled -c 192.168.1.10");
cmd_svc_configure.addArgFlagString("-n", "svcname",   "Service internal name");
cmd_svc_configure.addArgFlagString("-s", "starttype", "New start type: auto | demand | disabled | boot | system", "");
cmd_svc_configure.addArgFlagString("-p", "binpath",   "New binary path (optional)", "");
cmd_svc_configure.addArgFlagString("-d", "dispname",  "New display name (optional)", "");
cmd_svc_configure.addArgFlagString("-c", "computer",  "Remote machine (skip = localhost)", "localhost");
cmd_svc_configure.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var svcname    = parsed_json["svcname"]   || "";
    var starttype  = parsed_json["starttype"] || "";
    var binpath    = parsed_json["binpath"]   || "";
    var dispname   = parsed_json["dispname"]  || "";
    var computer   = parsed_json["computer"]  || "localhost";
    if (!svcname) { ax.console_message(id, "missing -n <svcname>", "error"); return; }
    if (!starttype && !binpath && !dispname) {
        ax.console_message(id, "specify at least one of: -s <starttype> | -p <binpath> | -d <dispname>", "error");
        return;
    }
    var bof_path   = ax.script_dir() + "_bin/svcmgr." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("cstr,cstr,cstr,cstr,cstr,cstr",
        ["configure", computer, svcname, starttype, binpath, dispname]);
    ax.execute_alias(id, cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: svc_configure [" + svcname + "] on " + computer, null);
});

// ── Register group ───────────────────────────────────────────
var group_svc = ax.create_commands_group("SvcMgr-BOF", [
    cmd_svc_list,
    cmd_svc_query,
    cmd_svc_create,
    cmd_svc_delete,
    cmd_svc_start,
    cmd_svc_stop,
    cmd_svc_configure
]);
ax.register_commands_group(group_svc, ["beacon", "gopher", "kharon", "NoNameAx"], ["windows"], []);
