var metadata = {
    name: "",
    description: "",
    nosave: true
};

var path = ax.script_dir();
ax.script_load(path + "clipboard/clipboard.axs");
ax.script_load(path + "EdrEnum-BOF/edr.axs");
ax.script_load(path + "Keylogger-BOF/keylog.axs");
ax.script_load(path + "wifi/wifidump.axs");
ax.script_load(path + "ghost_task/ghost_task.axs");
ax.script_load(path + "sc_bof/svcmgr.axs");
ax.script_load(path + "fw/fw.axs");
ax.script_load(path + "reg/reg.axs");
ax.script_load(path + "tgt-monitor/tgt_monitor.axs");
ax.script_load(path + "timestomp/timestomp.axs");
ax.script_load(path + "zip-bof/ax_zip.axs");
ax.script_load(path + "privesc/privesc.axs");
