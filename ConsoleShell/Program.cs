using System.Text;
using Malward.Engine.Config;
using Malward.Engine.Util;

namespace Malward.ConsoleShell;

public static class Program
{
    public static int Main(string[] args)
    {
        try { Console.OutputEncoding = Encoding.UTF8; } catch { }

        try { return Dispatch(args); }
        finally { Con.HoldWindow(); }
    }

    private static int Dispatch(string[] args)
    {
        if (args.Length == 0)
        {
            Help.Top();
            return 0;
        }

        var verb = args[0].TrimStart('/', '-').ToLowerInvariant();
        var rest = new CommandLine(args.Skip(1));

        try
        {
            return verb switch
            {
                "scan"       => ScanShell.Run(rest),
                "quarmng"    => QuarantineShell.Run(rest),
                "exclusions" => ExclusionShell.Run(rest),
                "update"     => Update(),
                "ver"        => Version(),
                "help" or "?" => Ok(() => Help.Top(rest)),
                _            => Unknown(args[0]),
            };
        }
        catch (Exception ex)
        {
            Con.ErrorLine($"[!] {ex.Message}");
            return 10;
        }
    }

    private static int Ok(Action a) { a(); return 0; }

    private static int Unknown(string verb)
    {
        Con.ErrorLine($"[!] Unknown command: {verb}");
        Con.ErrorLine("    Run  malcsm /help  for the list of commands.", Tone.Dim);
        return 2;
    }

    private static readonly (string Key, string Name)[] UpdateComponents =
    {
        ("vps",       "Threat signatures"),
        ("heur",      "Heuristic rules"),
        ("whitelist", "Detection signatures"),
    };

    private static int Update()
    {
        Con.Banner("database update");

        var settings = new Settings();
        var real = Console.Out;
        var block = new StatusBlock(real);

        var state = new Dictionary<string, (string Phase, double Pct)>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, _) in UpdateComponents) state[key] = ("waiting", 0);

        void Draw(bool force)
        {
            var rows = new List<IReadOnlyList<string>>();
            var tones = new List<Tone>();
            double total = 0;
            foreach (var (key, name) in UpdateComponents)
            {
                var (phase, pct) = state[key];
                total += phase is "updated" or "current" ? 1 : pct;
                rows.Add(new[] { name, Describe(phase, pct) });
                tones.Add(phase == "waiting" ? Tone.Dim : Tone.Info);
            }

            var lines = new List<StatusLine> { new("Malward database update", Tone.Title), "" };
            foreach (var (text, tone) in Con.TableLines(new[] { "DATABASE", "STATUS" }, rows, tones))
                lines.Add(new StatusLine(text, tone));
            lines.Add("");
            lines.Add(new StatusLine($"Completed: {total / UpdateComponents.Length * 100:F1}%", Tone.Info));
            block.Render(lines, force);
        }

        Draw(true);

        var diag = new StringWriter();
        using var errors = new ErrorScope(diag);
        var realErr = errors.Previous;

        try
        {
            using var sink = new StringWriter();
            using var svc = new Malward.Engine.Cloud.UpdateService(settings);
            svc.Progress = (component, phase, pct) =>
            {
                if (!state.ContainsKey(component)) return;
                state[component] = (phase, pct);
                Draw(phase is "updated" or "current");
            };

            int n;
            using (ConsoleRouter.Scope(sink))
                n = svc.UpdateAllAsync().GetAwaiter().GetResult();

            foreach (var (key, _) in UpdateComponents)
                if (state[key].Phase is "waiting" or "checking" or "downloading")
                    state[key] = ("current", 1);
            Draw(true);
            block.Release();

            real.WriteLine();
            Con.Line(n > 0
                ? $"Done — {n} database(s) refreshed."
                : "Done — everything was already up to date.", Tone.Info);
            return 0;
        }
        catch (Exception ex)
        {
            block.Release();
            realErr.WriteLine();
            Con.Write(realErr, $"[!] Update failed: {ex.Message}", Tone.Warn);
            realErr.WriteLine();
            foreach (var line in diag.ToString().Split('\n'))
                if (line.Trim().Length > 0)
                {
                    Con.Write(realErr, "    " + line.Trim(), Tone.Dim);
                    realErr.WriteLine();
                }
            return 6;
        }
    }

    private static string Describe(string phase, double pct) => phase switch
    {
        "waiting"     => "waiting",
        "checking"    => "checking…",
        "downloading" => $"downloading {pct * 100,5:F1}%",
        "updated"     => "updated",
        _             => "up to date",
    };

    private static int Version()
    {
        Con.Banner("");

        var asm = System.Reflection.Assembly.GetExecutingAssembly();
        var ver = asm.GetName().Version?.ToString() ?? "unknown";

        Con.Line($"  version     : {ver}", Tone.Dim);
        Con.Line($"  data folder : {Paths.DataDir}", Tone.Dim);
        Con.Line();
        Con.Line("Detection databases", Tone.Title);

        var rows = new List<IReadOnlyList<string>>();
        foreach (var e in DatabaseInfo.Listed)
        {
            if (!DatabaseInfo.Installed(e)) continue;
            var build = DatabaseInfo.Version(e.VersionKey);
            rows.Add(new[] { e.Name, build.Length == 0 ? "unknown" : build, DatabaseInfo.BuildDate(e) });
        }

        if (rows.Count == 0)
        {
            Con.Line();
            Con.Line("No databases found — run  malcsm /update  first.", Tone.Warn);
            return 1;
        }

        Con.Table(new[] { "DATABASE", "BUILD", "UPDATED" }, rows,
                  rows.Select(_ => Tone.Plain).ToList());
        return 0;
    }
}
