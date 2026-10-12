namespace Malward.ResidentShield.Hips;

public static class HipsRules
{
    public enum Category { File, Registry, Action, Process }

    public enum Mode
    {
        Log,

        Ask,

        Block,
    }

    public sealed record Rule(
        string Id, Category Category, string Name, string Description,
        string Detector, Mode Default = Mode.Ask);

    private static readonly Rule[] FileRules =
    {
        new("file.startup", Category.File, "", "",
            "FileWatcher:startup", Mode.Block),
        new("file.startup_ext", Category.File, "", "",
            "FileWatcher:startup-all", Mode.Block),
        new("file.tasks", Category.File, "", "",
            "FileWatcher:tasks", Mode.Block),
        new("file.hosts", Category.File, "", "",
            "FileWatcher:hosts", Mode.Block),

        new("file.system", Category.File, "", "",
            "FileWatcher:system32", Mode.Block),
        new("file.autorun_usb", Category.File, "", "",
            "FileWatcher:autorun", Mode.Block),
        new("file.ads", Category.File, "", "",
            "FileWatcher:ads"),

        new("file.shortcuts", Category.File, "", "",
            "FileWatcher:shortcuts", Mode.Block),
        new("file.suspicious_create", Category.File, "", "",
            "SuspiciousWrite"),
        new("file.infector", Category.File, "", "",
            "FileInfector", Mode.Block),

        new("file.self_replicate", Category.File, "", "",
            "Replicator", Mode.Block),
        new("file.psprofile", Category.File, "", "",
            "FileWatcher:psprofile", Mode.Block),
        new("file.gpo_scripts", Category.File, "", "",
            "FileWatcher:gposcripts", Mode.Block),
        new("file.office", Category.File, "", "",
            "FileWatcher:office", Mode.Block),
        new("file.sys_subdirs", Category.File, "", "",
            "FileWatcher:sysdirs"),
        new("file.systemp", Category.File, "", "",
            "FileWatcher:systemp"),
        new("file.badip_source", Category.File, "", "",
            "FileWatcher:badip", Mode.Block),
        new("file.accessibility", Category.File, "", "",
            "FileWatcher:accessibility", Mode.Block),
    };

    private static readonly Rule[] RegistryRules =
    {
        new("reg.run", Category.Registry, "", "",
            "Registry:autorun", Mode.Block),
        new("reg.winlogon", Category.Registry, "", "",
            "Registry:winlogon", Mode.Block),
        new("reg.appinit", Category.Registry, "", "",
            "Registry:appinit", Mode.Block),
        new("reg.ifeo", Category.Registry, "", "",
            "Registry:ifeo", Mode.Block),
        new("reg.services", Category.Registry, "", "",
            "Registry:services", Mode.Block),
        new("reg.safeboot", Category.Registry, "", "",
            "Registry:safeboot", Mode.Block),
        new("reg.file_assoc", Category.Registry, "", "",
            "Registry:fileassoc", Mode.Block),
        new("reg.policy_lock", Category.Registry, "", "",
            "Registry:policylock", Mode.Block),
        new("reg.uac", Category.Registry, "", "",
            "Registry:uac", Mode.Block),
        new("reg.com_hijack", Category.Registry, "", "",
            "Registry:comhijack", Mode.Block),
        new("reg.shell_ext", Category.Registry, "", "",
            "Registry:shellext"),

        new("reg.script_host", Category.Registry, "", "",
            "Registry:scripthost", Mode.Block),
        new("reg.proxy", Category.Registry, "", "",
            "Registry:proxy"),

        new("reg.driver_blocklist", Category.Registry, "", "",
            "Registry:driverblock", Mode.Block),
        new("reg.service_config", Category.Registry, "", "",
            "Registry:serviceconfig", Mode.Block),
        new("reg.defender_policy", Category.Registry, "", "",
            "Registry:defenderpolicy", Mode.Block),
        new("reg.firewall_policy", Category.Registry, "", "",
            "Registry:firewallpolicy", Mode.Block),
        new("reg.lsa_providers", Category.Registry, "", "",
            "Registry:lsaproviders", Mode.Block),
        new("reg.dll_loadpoints", Category.Registry, "", "",
            "Registry:dllloadpoints", Mode.Block),
        new("reg.session_manager", Category.Registry, "", "",
            "Registry:sessionmanager", Mode.Block),
        new("reg.aedebug", Category.Registry, "", "",
            "Registry:aedebug", Mode.Block),
        new("reg.active_setup", Category.Registry, "", "",
            "Registry:activesetup", Mode.Block),
        new("reg.environment", Category.Registry, "", "",
            "Registry:environment", Mode.Block),
        new("reg.system_restore", Category.Registry, "", "",
            "Registry:systemrestore", Mode.Block),
        new("reg.rdp", Category.Registry, "", "",
            "Registry:rdp", Mode.Block),
        new("reg.dns", Category.Registry, "", "",
            "Registry:dns", Mode.Block),
        new("reg.shell_folders", Category.Registry, "", "",
            "Registry:shellfolders", Mode.Block),
        new("reg.accounts", Category.Registry, "", "",
            "Registry:accounts", Mode.Block),
        new("reg.gpo_scripts", Category.Registry, "", "",
            "Registry:gposcripts", Mode.Block),
        new("reg.wmi_subscription", Category.Registry, "", "",
            "Wmi:subscription", Mode.Block),
    };

    private static readonly Rule[] ActionRules =
    {
        new("act.ps_hidden", Category.Action, "", "",
            "LolBinHiddenScript", Mode.Block),
        new("act.script_download", Category.Action, "", "",
            "LolBinDownload", Mode.Block),
        new("act.remote_script", Category.Action, "", "",
            "LolBinRemoteScript", Mode.Block),
        new("act.wmic", Category.Action, "", "",
            "LolBinWmic", Mode.Block),
        new("act.shadow_delete", Category.Action, "", "",
            "ShadowCopyDeletion", Mode.Block),
        new("act.boot_tamper", Category.Action, "", "",
            "BootConfigTamper", Mode.Block),
        new("act.defender_off", Category.Action, "", "",
            "DefenderDisable", Mode.Block),
        new("act.defender_excl", Category.Action, "", "",
            "DefenderExclusion", Mode.Block),
        new("act.firewall_off", Category.Action, "", "",
            "FirewallDisable", Mode.Block),
        new("act.log_tamper", Category.Action, "", "",
            "LogTampering", Mode.Block),
        new("act.free_space_wipe", Category.Action, "", "",
            "FreeSpaceWipe", Mode.Block),
        new("act.cred_dump", Category.Action, "", "",
            "Registry:credtheft", Mode.Block),
        new("act.account_change", Category.Action, "", "",
            "AccountChange", Mode.Ask),
        new("act.service_delete", Category.Action, "", "",
            "SecurityServiceDisable", Mode.Block),
        new("act.proc_kill", Category.Action, "", "",
            "CriticalProcessKill", Mode.Block),
        new("act.task_create", Category.Action, "", "",
            "Persistence", Mode.Block),
        new("act.miner", Category.Action, "", "",
            "CryptoMiner", Mode.Block),
        new("act.recon", Category.Action, "", "",
            "ReconBurst"),
        new("act.anon_c2", Category.Action, "", "",
            "AnonymisedC2", Mode.Block),
        new("act.chain", Category.Action, "", "",
            "SuspiciousChain"),
    };

    private static readonly Rule[] ProcessRules =
    {
        new("proc.critical", Category.Process, "", "",
            "DefenseImpairment", Mode.Block),
        new("proc.explorer", Category.Process, "", "",
            "ExplorerTamper", Mode.Ask),
        new("proc.spoof", Category.Process, "", "",
            "ProcessSpoofing", Mode.Block),
        new("proc.child_spawn", Category.Process, "", "",
            "ExcessiveChildSpawning"),

        new("proc.self_copy", Category.Process, "", "",
            "SelfReplication", Mode.Block),
        new("proc.lsass_access", Category.Process, "", "",
            "Injection:lsass", Mode.Block),

        new("proc.unsigned_dll", Category.Process, "", "",
            "UnsignedModuleLoad", Mode.Log),
    };

    public static IReadOnlyList<Rule> All { get; } =
        Localise(FileRules.Concat(RegistryRules).Concat(ActionRules).Concat(ProcessRules).ToArray());

    private static Rule[] Localise(Rule[] rules)
    {
        var text = new Dictionary<string, (string Name, string Desc)>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var line in Malward.Engine.Data.SignatureStore.List("hips_rule_text"))
            {
                var parts = line.Split('\u001F');
                if (parts.Length >= 3 && parts[0].Length > 0) text[parts[0]] = (parts[1], parts[2]);
            }
        }
        catch {  }

        if (text.Count == 0)
        {
            Log.Warn("HIPS", "No rule texts in the signature database — the UI will show identifiers " +
                             "instead of names and descriptions. Regenerate sigdata.vdeb (malscan make-sigdata).");
            return rules.Select(r => r with { Name = r.Id, Description = "" }).ToArray();
        }

        var missing = new List<string>();
        var result = rules.Select(r =>
        {
            if (text.TryGetValue(r.Id, out var t) && t.Name.Length > 0)
                return r with { Name = t.Name, Description = t.Desc };
            missing.Add(r.Id);
            return r with { Name = r.Id, Description = "" };
        }).ToArray();

        if (missing.Count > 0)
            Log.Warn("HIPS", $"Descriptions of {missing.Count} rules are missing from the signature database: " +
                             string.Join(", ", missing.Take(5)) + (missing.Count > 5 ? "…" : ""));
        return result;
    }

    public static IEnumerable<Rule> ByCategory(Category c) => All.Where(r => r.Category == c);

    public static IEnumerable<Rule> ForDetector(string detector) =>
        All.Where(r => r.Detector.Equals(detector, StringComparison.OrdinalIgnoreCase));

    private static readonly HashSet<string> Wired = new(StringComparer.OrdinalIgnoreCase);

    public static void MarkWired(IEnumerable<string> detectors)
    {
        foreach (var d in detectors)
            if (!string.IsNullOrWhiteSpace(d)) Wired.Add(d);
    }

    public static bool IsLive(Rule r) =>
        !r.Detector.Contains(':') || Wired.Contains(r.Detector);

    public static Rule? ById(string id) =>
        All.FirstOrDefault(r => r.Id.Equals(id, StringComparison.OrdinalIgnoreCase));

    public static readonly string[] Tiers = { "low", "medium", "high", "paranoic" };

    private static readonly string[] MediumExtra =
    {
        "reg.run", "reg.winlogon", "reg.services", "reg.service_config", "reg.ifeo",
        "reg.defender_policy", "reg.firewall_policy", "reg.safeboot", "reg.uac", "reg.dns",
        "reg.appinit", "reg.wmi_subscription", "reg.active_setup", "reg.policy_lock", "reg.system_restore",
        "file.startup", "file.startup_ext", "file.tasks", "file.hosts", "file.accessibility",
        "file.badip_source", "file.self_replicate", "file.infector",
    };
    private static readonly string[] HighExtraFiles =
    {
        "file.psprofile", "file.shortcuts", "file.gpo_scripts", "file.autorun_usb",
        "file.suspicious_create", "file.ads", "file.office",
    };

    public static HashSet<string> TierIds(string? tier)
    {
        var t = (tier ?? "medium").Trim().ToLowerInvariant();
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (t == "paranoic") { foreach (var r in All) set.Add(r.Id); return set; }
        foreach (var r in All) if (r.Category is Category.Action or Category.Process) set.Add(r.Id);
        if (t == "low") return set;
        foreach (var id in MediumExtra) set.Add(id);
        if (t != "high") return set;
        foreach (var r in All) if (r.Category == Category.Registry) set.Add(r.Id);
        foreach (var id in HighExtraFiles) set.Add(id);
        return set;
    }

    public static void ExportCatalog()
    {
        try
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Malward", "data");
            Directory.CreateDirectory(dir);
            var arr = new System.Text.Json.Nodes.JsonArray();
            foreach (var r in All)
            {
                if (string.IsNullOrEmpty(r.Detector)) continue;
                arr.Add(new System.Text.Json.Nodes.JsonObject
                {
                    ["id"] = r.Id,
                    ["category"] = r.Category.ToString().ToLowerInvariant(),
                    ["name"] = r.Name,
                    ["desc"] = r.Description,
                    ["default"] = r.Default.ToString().ToLowerInvariant(),

                    ["live"] = IsLive(r),
                });
            }
            var o = new System.Text.Json.Nodes.JsonObject { ["rules"] = arr };
            File.WriteAllText(Path.Combine(dir, "hips-catalog.json"), Malward.ResidentShield.JsonText.Indented(o));
        }
        catch (Exception ex)
        {
            Log.Warn("HIPS", $"Failed to export the rule catalog: {ex.GetType().Name}: {ex.Message}");
        }
    }
}
