var metadata = {
    name: "PrivEsc-BOF",
    description: "Detect and enable disabled token privileges on the current process"
};

// -----------------------------------------------------------------------
// privesc    : Enable all disabled privileges (default)
// privesc -l : List only, no changes
// privesc -n : SeDebugPrivilege — Enable a specific privilege
// -----------------------------------------------------------------------

var cmd_privesc = ax.create_command( "privesc", "Detect disabled token privileges and enable them. Runs on current process token.", "privesc | privesc -l | privesc -n SeDebugPrivilege");
cmd_privesc.addArgBool("-l", "List privileges only, do not enable anything");
cmd_privesc.addArgFlagString("-n", "name", "Enable only this specific privilege (e.g. SeDebugPrivilege)", "");

cmd_privesc.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {

    var list_only = parsed_json["-l"] ? 1 : 0;
    var priv_name = parsed_json["name"] || "";

    var bof_params = ax.bof_pack("int,cstr", [list_only, priv_name]);
    var bof_path   = ax.script_dir() + "_bin/privesc." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: PrivEsc — enable token privileges");
});

var group_privesc = ax.create_commands_group("PrivEsc-BOF", [cmd_privesc]);
ax.register_commands_group(group_privesc, ["beacon", "gopher", "kharon", "NoNameAx"], ["windows"], []);
