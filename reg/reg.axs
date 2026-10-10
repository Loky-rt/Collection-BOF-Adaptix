var metadata = {
    name: "Reg-BOF",
    description: "Windows Registry interaction BOF (query, add, delete)"
};

let _cmd_reg_query = ax.create_command("reg_query", "Query a registry key or value", "reg_query HKLM \"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\" ProductName");
_cmd_reg_query.addArgString("hive", true, "Registry hive: HKLM, HKCU, HKCR, HKU, HKCC");
_cmd_reg_query.addArgString("key", true, "Registry key path");
_cmd_reg_query.addArgString("value", false, "Value name (omit to list all values)");
_cmd_reg_query.addArgFlagString("-m", "machine", "Remote machine hostname", "");
_cmd_reg_query.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let hive    = parsed_json["hive"];
    let key     = parsed_json["key"];
    let value   = parsed_json["value"]   || "";
    let machine = parsed_json["machine"] || "";

    if (value.startsWith("-")) value = "";

    let params = "reg_query " + hive + " \"" + key + "\"";
    if (value.length > 0)   params += " \"" + value + "\"";
    if (machine.length > 0) params += " /machine:" + machine;

    let bof_params = ax.bof_pack("cstr", [params]);
    let bof_path = ax.script_dir() + "_bin/reg." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: Registry QUERY");
});

let _cmd_reg_add = ax.create_command("reg_add", "Add or modify a registry value", "reg_add HKLM \"SOFTWARE\\Test\" MyValue REG_SZ \"Hello World\"");
_cmd_reg_add.addArgString("hive", true, "Registry hive: HKLM, HKCU, HKCR, HKU, HKCC");
_cmd_reg_add.addArgString("key", true, "Registry key path");
_cmd_reg_add.addArgString("value", true, "Value name");
_cmd_reg_add.addArgString("type", true, "REG_SZ | REG_DWORD | REG_QWORD | REG_BINARY | REG_EXPAND_SZ | REG_MULTI_SZ");
_cmd_reg_add.addArgString("data", true, "Data to write. DWORD/QWORD: 1234 or 0x4d2 | BINARY: AABBCC | MULTI_SZ: val1|val2|val3");
_cmd_reg_add.addArgFlagString("-m", "machine", "Remote machine hostname", "");
_cmd_reg_add.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let hive    = parsed_json["hive"];
    let key     = parsed_json["key"];
    let value   = parsed_json["value"];
    let type    = parsed_json["type"];
    let data    = parsed_json["data"];
    let machine = parsed_json["machine"] || "";

    let params = "reg_add " + hive + " \"" + key + "\" \"" + value + "\" " + type + " \"" + data + "\"";
    if (machine.length > 0) params += " /machine:" + machine;

    let bof_params = ax.bof_pack("cstr", [params]);
    let bof_path = ax.script_dir() + "_bin/reg." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: Registry ADD");
});

let _cmd_reg_delete = ax.create_command("reg_delete", "Delete a registry key or value", "reg_delete HKLM \"SOFTWARE\\Test\" MyValue");
_cmd_reg_delete.addArgString("hive", true, "Registry hive: HKLM, HKCU, HKCR, HKU, HKCC");
_cmd_reg_delete.addArgString("key", true, "Registry key path");
_cmd_reg_delete.addArgString("value", false, "Value name (omit to delete entire key including subkeys)");
_cmd_reg_delete.addArgFlagString("-m", "machine", "Remote machine hostname", "");
_cmd_reg_delete.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let hive    = parsed_json["hive"];
    let key     = parsed_json["key"];
    let value   = parsed_json["value"]   || "";
    let machine = parsed_json["machine"] || "";

    if (value.startsWith("-")) value = "";

    let params = "reg_delete " + hive + " \"" + key + "\"";
    if (value.length > 0)   params += " \"" + value + "\"";
    if (machine.length > 0) params += " /machine:" + machine;

    let bof_params = ax.bof_pack("cstr", [params]);
    let bof_path = ax.script_dir() + "_bin/reg." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: Registry DELETE");
});


// var cmd_reg = ax.create_command("reg", "Windows Registry interaction (query, add, delete)");
// cmd_reg.addSubCommands([_cmd_reg_query, _cmd_reg_add, _cmd_reg_delete]);

// var group_reg = ax.create_commands_group("Reg-BOF", [cmd_reg]);
// ax.register_commands_group(group_reg, ["beacon", "gopher", "kharon"], ["windows"], []);


var group_reg = ax.create_commands_group("Reg-BOF", [
    _cmd_reg_query,
    _cmd_reg_add,
    _cmd_reg_delete
]);
ax.register_commands_group(group_reg, ["beacon", "gopher", "kharon", "NoNameAx"], ["windows"], []);
