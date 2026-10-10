var metadata = {
    name: "ZIP-BOF",
    description: "Compress files and directories into ZIP archives on the target"
};

// -----------------------------------------------------------------------
// zip — Compress a file or directory into a ZIP archive (STORED, no compression)
// -----------------------------------------------------------------------
var cmd_zip = ax.create_command(
    "zip",
    "Compress a file or directory recursively into a ZIP archive on the target (STORED format, no compression). The output ZIP is created on the target filesystem and must be downloaded manually.",
    "zip -s C:\\Users\\john\\Documents -o C:\\Windows\\Temp\\docs.zip | zip -s C:\\Windows\\System32\\config -o C:\\Temp\\config.zip"
);
cmd_zip.addArgFlagString("-s", "source", "Source path — file or directory to compress (required)", "");
cmd_zip.addArgFlagString("-o", "output", "Output ZIP file path on the target (required)",          "");

cmd_zip.setPreHook(function (id, cmdline, parsed_json) {
    var source = parsed_json["source"] || "";
    var output = parsed_json["output"] || "";

    if (!source) {
        ax.console_message(id, "zip: -s <source> is required", "error");
        return;
    }
    if (!output) {
        ax.console_message(id, "zip: -o <output> is required", "error");
        return;
    }

    var bof_params = ax.bof_pack("cstr,cstr", [source, output]);
    var bof_path   = ax.script_dir() + "_bin/zip." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline,
        `execute bof "${bof_path}" ${bof_params}`,
        "Task: ZIP [" + source + " -> " + output + "]");
});

// -----------------------------------------------------------------------
// Register commands group
// -----------------------------------------------------------------------
var group_zip = ax.create_commands_group("ZIP-BOF", [cmd_zip]);
ax.register_commands_group(group_zip, ["beacon", "gopher", "NoNameAx"], ["windows"], []);
