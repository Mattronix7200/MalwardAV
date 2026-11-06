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
        }

        Con.Line("Every setting comes from the command line; the graphical program's", Tone.Dim);
        Con.Line("configuration is never read or written.", Tone.Dim);
        Con.Line();

        Head("USAGE");
        Row("malcsm /scan <mode> [options]", "run a scan");
        Row("malcsm /quarmng <option>", "quarantine manager");
        Row("malcsm /update", "update the detection databases");
        Row("malcsm /ver", "program and database versions");
        Row("malcsm /exclusions <option>", "manage scan exclusions");
        Row("malcsm /help [topic]", "this text, or one section of it");
        Con.Line();
        Con.Line("  Switches accept both forms: /q and --quick.", Tone.Dim);
        Con.Line("  Nothing is on by default: with no switches the scan compares files against", Tone.Dim);
        Con.Line("  the signature database, applies no size limits and repairs nothing. Add", Tone.Dim);
        Con.Line("  /a /h /cs to turn layers on and /fix to act on what is found. The file", Tone.Dim);
        Con.Line("  whitelist always filters the results and cannot be turned off.", Tone.Dim);
        Con.Line();

        Scan();
        Con.Line();
        Con.Line("  More: malcsm /help quarmng | exclusions | update", Tone.Dim);
    }

    public static void Scan()
    {
        Head("/scan — SCAN SHELL");
        Con.Line("  mode (pick one)", Tone.Dim);
        Row("/q,  --quick", "quick scan of the usual infection points");
        Row("/f,  --full", "full scan of every fixed drive");
        Row("/c,  --custom <path>…", "scan the given files or folders");
        Con.Line();
        Con.Line("  detection layers                                                  default", Tone.Dim);
        Row("/m,  --memory", "scan running processes", "off");
        Row("/a,  --archive", "look inside archives", "off");
        Row("/h,  --heur", "heuristic analysis", "off");

        Row("/cs, --enable-cloud-scan", "cloud scanning", "off");
        Row("/cv, --enable-cloud-verify", "verify hits in the cloud", "off");
        Row("/cc, --use-cloud-cache", "skip what the cloud knows", "off");
        Row("/ss, --skip-signed", "skip Microsoft-signed files", "off");
        Con.Line();
        Con.Line("  speed and limits", Tone.Dim);
        Row("/t,    --threads <n>", "parallel scanning threads", "cores");
        Row("/cpu,  --cpu-limit <percent>", "cap the processor budget", "100");
        Row("/mfs,  --max-file-size <MB>", "largest file scanned", "no limit");
        Row("/mct,  --max-cloud-time <s>", "wait for a cloud verdict", "30");
        Row("/mut,  --max-upload-time <s>", "time budget per file", "60");
        Row("/amfs, --archive-max-file-size <MB>", "largest archive opened", "no limit");
        Row("/amn,  --archive-max-nesting <n>", "archive nesting depth", "12");
        Con.Line();
        Con.Line("  what to do with a threat", Tone.Dim);
        Row("/auto, --autofix", "repair automatically", "off");
        Row("/fix 1 | --fix-quar", "move to quarantine");
        Row("/fix 2 | --fix-del", "delete");
        Row("/fix 3 | --fix-ask", "ask after the scan");
        Row("/fix 4 | --fix-ignore", "only report");
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
        Con.Line("  example", Tone.Dim);
        Con.Line("    malcsm /scan /c \"D:\\data\" /h /cs /fix 3 /ext 2 {log,tmp}", Tone.Info);
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
