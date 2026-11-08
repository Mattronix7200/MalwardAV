namespace Malward.ConsoleShell;

public static class Help
{
    private static void Head(string text) => Con.Line(text, Tone.Title);

    private static void Row(string option, string description, string dflt = "")
    {
        var column = option.Length >= 36 ? option + "  " : option.PadRight(36);
        Con.Write(Console.Out, "    " + column, Tone.Info);
        Con.Write(Console.Out, description.PadRight(dflt.Length > 0 ? 34 : 0), Tone.Plain);
        if (dflt.Length > 0) Con.Write(Console.Out, dflt, Tone.Dim);
        Console.Out.Write(Environment.NewLine);
    }

    public static void Top(CommandLine? cl = null)
    {
        var topic = (cl?.Positional().FirstOrDefault() ?? "").Trim().ToLowerInvariant();

        Con.Banner("portable console scanner");

        switch (topic)
        {
            case "scan":       Scan(); return;
            case "quarmng":    Quarantine(); return;
            case "exclusions": Exclusions(); return;
            case "update":     Update(); return;
            case "settings":   SettingsFile(); return;
        }

        Con.Line("Start malcsm with no arguments for the full-screen menu, or drive it", Tone.Dim);
        Con.Line("from the command line with the commands below.", Tone.Dim);
        Con.Line();

        Head("USAGE");
        Row("malcsm", "full-screen menu");
        Row("malcsm /scan /q | /f | <path>", "run a scan");
        Row("malcsm /quarmng <option>", "quarantine manager");
        Row("malcsm /update", "update the detection databases");
        Row("malcsm /ver", "program and database versions");
        Row("malcsm /exclusions <option>", "manage scan exclusions");
        Row("malcsm /help [topic]", "this text, or one section of it");
        Con.Line();
        Con.Line("  Switches accept both forms: /q and --quick.", Tone.Dim);
        Con.Line("  The cloud layers and the whitelist layers are ON by default, the same way", Tone.Dim);
        Con.Line("  the graphical scanner runs them, so a database hit is confirmed before it", Tone.Dim);
        Con.Line("  is reported. Turning any of them off makes false positives likely and the", Tone.Dim);
        Con.Line("  scanner says so on screen and in the report.", Tone.Dim);
        Con.Line("  Every switch below also accepts  on | off  after it, so  /cs off  turns the", Tone.Dim);
        Con.Line("  layer off for one run without touching the stored settings.", Tone.Dim);
        Con.Line();

        Scan();
        Con.Line();
        Con.Line("  More: malcsm /help quarmng | exclusions | update | settings", Tone.Dim);
    }

    public static void Scan()
    {
        Head("/scan — SCAN SHELL");
        Con.Line("  mode (pick one)", Tone.Dim);
        Row("/q,  --quick", "quick scan of the usual infection points");
        Row("/f,  --full", "full scan of every fixed drive");
        Row("<path> [<path>…]", "scan the given files or folders");
        Con.Line();
        Con.Line("    /c was removed: give the path on its own, with no switch in front of it.", Tone.Dim);
        Con.Line();
        Con.Line("  detection layers                                                  default", Tone.Dim);
        Row("/cs, --enable-cloud-scan", "cloud scanning", "on");
        Row("/cv, --enable-cloud-verify", "verify hits in the cloud", "on");
        Row("/cc, --use-cloud-cache", "skip what the cloud knows", "on");
        Row("/ss, --skip-signed", "skip Microsoft-signed files", "on");
        Row("/m,  --memory", "scan running processes", "off");
        Row("/a,  --archive", "look inside archives", "off");
        Row("/h,  --heur", "heuristic analysis", "off");
        Row("--offline", "turn every cloud layer off at once");
        Con.Line();
        Con.Line("  speed and limits", Tone.Dim);
        Row("/t,    --threads <n>", "parallel scanning threads", "cores");
        Row("/cpu,  --cpu-limit <percent>", "cap the processor budget", "100");
        Row("/mfs,  --max-file-size <MB>", "largest file scanned, 0 = no limit", "100");
        Row("/mct,  --max-cloud-time <s>", "wait for a cloud verdict", "30");
        Row("/mut,  --max-upload-time <s>", "time budget per file", "60");
        Row("/amfs, --archive-max-file-size <MB>", "largest archive opened, 0 = no limit", "250");
        Row("/amn,  --archive-max-nesting <n>", "archive nesting depth", "5");
        Con.Line();
        Con.Line("  what to do with a threat", Tone.Dim);
        Row("/auto, --autofix", "repair automatically", "off");
        Row("/fix 1 | --fix-quar", "move to quarantine");
        Row("/fix 2 | --fix-del", "delete");
        Row("/fix 3 | --fix-ask", "ask after the scan");
        Row("/fix 4 | --fix-ignore", "only report", "default");
        Row("/afix 1 | --archive-fix-copy", "drop the infected entry, keep the archive");
        Row("/afix 2 | --archive-fix-del", "delete the whole archive");
        Con.Line();
        Con.Line("  extensions", Tone.Dim);
        Row("/ext 0", "common executable extensions");
        Row("/ext 1", "every extension", "default");
        Row("/ext 2 {ext1,ext2,…}", "blacklist: scan everything except these");
        Row("/ext {ext1,ext2,…}", "scan only these");
        Con.Line();
        Con.Line("  report", Tone.Dim);
        Row("/log,  --log-output", "write the report to the Desktop without asking");
        Con.Line();
        Con.Line("  while a scan runs", Tone.Dim);
        Con.Line("    [Q] stops it. Ctrl+C is blocked so a half-finished repair cannot be", Tone.Dim);
        Con.Line("    interrupted between the file and the quarantine store.", Tone.Dim);
        Con.Line();
        Con.Line("  example", Tone.Dim);
        Con.Line("    malcsm /scan \"D:\\data\" /h /fix 3 /ext 2 {log,tmp}", Tone.Info);
    }

    public static void SettingsFile()
    {
        Head("SETTINGS");
        Con.Line("  The menu's Settings screen writes malcsm-settings.json next to the", Tone.Plain);
        Con.Line("  databases, and every scan starts from it. Switches on the command line", Tone.Plain);
        Con.Line("  override the stored value for that one run only.", Tone.Plain);
        Con.Line();
        Con.Line("  The graphical program's own configuration is never read or written.", Tone.Dim);
    }

    public static void Quarantine()
    {
        Head("/quarmng — QUARANTINE MANAGER");
        Row("/s,   --list", "list every quarantined item");
        Row("/v,   --view-item <id>", "details of one item");
        Row("/lp,  --search <text>", "search by name, path, detection, ID or date");
        Row("/x,   --extract <id> [dir]", "copy the file out, keep it in quarantine");
        Row("/rvt, --revert <id>", "restore to the original path and remove it");
        Con.Line();
        Con.Line("  The quarantine manager needs an elevated console. Without administrator", Tone.Warn);
        Con.Line("  rights it is blocked, and a scan runs in detect-only mode.", Tone.Warn);
    }

    public static void Exclusions()
    {
        Head("/exclusions — EXCLUSION SHELL");
        Row("/ea, --add-exclusion <path>", "exclude a file or folder");
        Row("/er, --remove-exclusion <id>", "remove an exclusion by ID");
        Row("/ev, --show-exclusions", "list exclusions with their IDs");
    }

    public static void Update()
    {
        Head("/update — DATABASE UPDATE");
        Con.Line("  Refreshes the threat signatures, the heuristic rules and the file whitelist", Tone.Plain);
        Con.Line("  from the cloud, and records their build numbers for /ver.", Tone.Plain);
    }
}
