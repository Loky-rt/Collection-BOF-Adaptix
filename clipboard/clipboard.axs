var metadata = {
    name: "clipboard",
    description: "Read clipboard contents via Win32 API (CF_TEXT / CF_UNICODETEXT)."
};

var cmd_clipboard = ax.create_command(
    "clipboard",
    "Read the current system clipboard contents [NOISE: low]",
    "clipboard"
);

cmd_clipboard.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {

    var bof_path = ax.script_dir() + "_bin/clipboard." + ax.arch(id) + ".o";

    if (!ax.file_exists(bof_path)) {
        ax.console_message(id,
            "BOF not found: " + bof_path,
            "error",
            "Compile clipboard.c and place the .o files under _bin/ next to this script."
        );
        return;
    }

    var hook = function (task) {
        if (!task.text) return task;

        var lines = task.text.split("\n");
        var out   = [];

        for (var i = 0; i < lines.length; i++) {
            var l = lines[i];
            if (/^\[Clipboard\s*\//.test(l)) {
                var fmt = /Unicode/.test(l) ? "Unicode" : "ANSI";
                out.push("[Clipboard capture — " + fmt + "]");
                continue;
            }
            out.push(l);
        }

        task.text = out.join("\n");
        return task;
    };

    ax.execute_alias_hook(
        id,
        cmdline,
        "execute bof " + bof_path,
        "Task: Clipboard capture (BOF)",
        hook
    );
});

var group_clipboard = ax.create_commands_group("clipboard", [cmd_clipboard]);
ax.register_commands_group(group_clipboard, ["beacon", "gopher", "kharon", "NoNameAx"], ["windows"], []);
