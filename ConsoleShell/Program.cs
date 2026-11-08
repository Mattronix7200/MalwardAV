using System.Text;
using Malward.Engine.Util;

namespace Malward.ConsoleShell;

public static class Program
{
    public static int Main(string[] args)
    {
        // UTF-8 tylko tam, gdzie konsola to uniesie. Na starym conhoscie ustawienie strony
        // kodowej 65001 nie naprawia rysowania, tylko zamienia polskie znaki w krzaki.
        if (!ConsoleWindow.LegacyConsole)
        {
            try { Console.OutputEncoding = Encoding.UTF8; } catch { }
        }
        ConsoleWindow.InstallInterruptGuard();

        bool interactive = args.Length == 0;
        try { return Dispatch(args); }
        finally
        {
            ConsoleWindow.Restore();
            if (!interactive && !ConsoleWindow.FullScreenUsed) Con.HoldWindow();
        }
    }

    private static int Dispatch(string[] args)
    {
        if (args.Length == 0) return MainMenu.Run();

        var verb = args[0].TrimStart('/', '-').ToLowerInvariant();
        var rest = new CommandLine(args.Skip(1));

        try
        {
            return verb switch
            {
                "scan"       => ScanShell.Run(rest),
                "quarmng"    => QuarantineShell.Run(rest),
                "exclusions" => ExclusionShell.Run(rest),
                "update"     => UpdateShell.Run(interactive: false),
                "menu" or "ui" => MainMenu.Run(),
                "ver" or "version" => Version(),
                "help" or "?" => Ok(() => Help.Top(rest)),
                _            => Fallback(args),
            };
        }
        catch (Exception ex)
        {
            ConsoleWindow.Restore();
            Con.ErrorLine($"[!] {ex.Message}");
            return 10;
        }
    }

    private static int Ok(Action action) { action(); return 0; }

    private static int Fallback(string[] args)
    {
        if (!CommandLine.IsSwitch(args[0]) && LooksLikePath(args[0]))
            return ScanShell.Run(new CommandLine(args));

        Con.ErrorLine($"[!] Unknown command: {args[0]}");
        Con.ErrorLine("    Run  malcsm /help  for the list of commands,", Tone.Dim);
        Con.ErrorLine("    or start malcsm with no arguments for the menu.", Tone.Dim);
        return 2;
    }

    private static bool LooksLikePath(string value)
    {
        try { return File.Exists(value) || Directory.Exists(value); }
        catch { return false; }
    }

    private static int Version()
    {
        Con.Banner("");

        var assembly = System.Reflection.Assembly.GetExecutingAssembly();
        var version = assembly.GetName().Version?.ToString() ?? "unknown";

        Con.Line($"  version     : {version}", Tone.Dim);
        Con.Line($"  data folder : {Paths.DataDir}", Tone.Dim);
        Con.Line();
        Con.Line("Detection databases", Tone.Title);

        var rows = new List<IReadOnlyList<string>>();
        foreach (var entry in DatabaseInfo.Listed)
        {
            if (!DatabaseInfo.Installed(entry)) continue;
            var build = DatabaseInfo.Version(entry.VersionKey);
            rows.Add(new[]
            {
                entry.Name,
                build.Length == 0 ? "unknown" : build,
                DatabaseInfo.BuildDate(entry),
            });
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
