var metadata = {
    name: "TimeStomp",
    description: "timestomp: modifies file timestamps (Creation, Access, Modification)."
};

let cmd_timestomp = ax.create_command(
    "timestomp",
    "timestomp: modifies file timestamps (Creation, Access, Modification).",
    "timestomp FileTarget FileSource | timestomp file1.txt file2.txt");

cmd_timestomp.addArgString("FileTarget", true);
cmd_timestomp.addArgString("FileSource", true);

cmd_timestomp.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) { 
    let FileTarget = parsed_json["FileTarget"]   || "";
    let FileSource = parsed_json["FileSource"]   || "";
    let bof_params = ax.bof_pack("cstr,cstr", [FileTarget,FileSource]);
    let bof_path = ax.script_dir() + "_bin/timestomp." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline,
    `execute bof "${bof_path}" ${bof_params}`,
    "Task: timestomp " + FileSource + " -> " + FileTarget, null);
});

let group_TimeStomp = ax.create_commands_group("TimeStomp", [cmd_timestomp]);
ax.register_commands_group(group_TimeStomp, ["beacon", "gopher", "NoNameAx"], ["windows"], []);
