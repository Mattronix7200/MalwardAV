using Malward.Engine.Core;
using Malward.Engine.Util;

namespace Malward.ConsoleShell;

public static class MainMenu
{
    private static readonly (string Key, string Label, string Hint)[] Entries =
    {
        ("1", "Start scan",         "quick, full or a path you type"),
        ("2", "Check for updates",  "refresh the detection databases"),
        ("3", "Settings",           "scan layers, limits and actions"),
        ("4", "Quarantine",         "what was moved out of the way"),
        ("5", "Exclusions",         "paths this scanner leaves alone"),
        ("6", "Databases",          "versions and build dates"),
        ("0", "Exit",               ""),
    };

    public static int Run()
    {
        ConsoleWindow.Enter();
        var screen = new Screen();
        var options = ScanOptions.Load();
        string message = "";

        while (true)
        {
            int prompt = Draw(screen, options, message);
            message = "";

            var input = screen.ReadLine(screen.ContentLeft + 13, prompt, 10);
            if (input == null) return 0;

            switch (input.Trim().ToLowerInvariant())
            {
                case "":
                    continue;
                case "0":
                case "q":
                case "exit":
                    return 0;
                case "1":
                    StartScan(screen, options);
                    options = ScanOptions.Load();
                    break;
                case "2":
                    UpdateShell.Run(interactive: true);
                    break;
                case "3":
                    SettingsShell.Run(options);
                    break;
                case "4":
                    ShowQuarantine(screen);
                    break;
                case "5":
                    ShowExclusions(screen);
                    break;
                case "6":
                    ShowDatabases(screen);
                    break;
                default:
                    message = $"Unknown choice: {input}";
                    break;
            }

            screen.Invalidate();
        }
    }

    private static void StartScan(Screen screen, ScanOptions options)
    {
        var plan = PickPlan(screen, options);
        if (plan == null) return;
        if (!Confirm(screen, options, plan)) return;
        ScanShell.Start(plan, options, interactive: true);
        screen.Invalidate();
    }

    private static ScanPlan? PickPlan(Screen screen, ScanOptions options)
    {
        string message = "";
        while (true)
        {
            screen.Sync();
            screen.Clear();
            screen.Sidebar(ScanShell.SidebarInfo());

            int left = screen.ContentLeft;
            int width = screen.ContentWidth;
            int bottom = screen.ContentBottom;
            int y = screen.ContentTop;

            screen.Put(left, y++, "START SCAN", Tone.Title);
            screen.Rule(left, y++, width);
            y++;
            screen.Put(left, y, " 1. ", Tone.Dim);
            screen.Put(left + 4, y++, "Quick scan", Tone.Info);
            screen.Put(left + 8, y++, "the usual infection points, memory and startup entries", Tone.Dim);
            y++;
            screen.Put(left, y, " 2. ", Tone.Dim);
            screen.Put(left + 4, y++, "Full scan", Tone.Info);
            screen.Put(left + 8, y++, "every fixed drive, from the root down", Tone.Dim);
            y++;
            screen.Put(left, y, " 3. ", Tone.Dim);
            screen.Put(left + 4, y++, "Custom path", Tone.Info);
            screen.Put(left + 8, y++, "type a file or a folder to scan", Tone.Dim);
            y++;
            screen.Put(left, y, " 0. ", Tone.Dim);
            screen.Put(left + 4, y++, "Back", Tone.Plain);

            if (message.Length > 0) screen.Put(left, bottom - 2, Screen.Clip(message, width), Tone.Warn);
            int prompt = bottom - 1;
            screen.Put(left, prompt, "Your choice:", Tone.Info);
            screen.Flush();

            var input = screen.ReadLine(left + 13, prompt, 10);
            if (input == null) return null;
            message = "";

            switch (input.Trim().ToLowerInvariant())
            {
                case "0": case "q": return null;
                case "1": return ScanPlan.Quick();
                case "2": return ScanPlan.Full();
                case "3":
                    var plan = AskPath(screen, ref message);
                    if (plan != null) return plan;
                    break;
                case "": break;
                default: message = $"Unknown choice: {input}"; break;
            }
        }
    }

    private static ScanPlan? AskPath(Screen screen, ref string message)
    {
        int left = screen.ContentLeft;
        int prompt = screen.ContentBottom - 1;
        const string label = "Path to scan: ";

        screen.Put(left, prompt, new string(' ', screen.ContentWidth));
        screen.Put(left, prompt, label, Tone.Info);
        screen.Flush();

        var typed = screen.ReadLine(left + label.Length, prompt, screen.ContentWidth - label.Length);
        if (typed == null || typed.Trim().Length == 0) return null;

        var plan = ScanShell.TargetPlan(new[] { typed }, out var error);
        if (error != null) { message = error; return null; }
        return plan;
    }

    private static bool Confirm(Screen screen, ScanOptions options, ScanPlan plan)
    {
        var warning = ScanShell.BuildWarning(options);
        if (warning == null) return true;

        screen.Sync();
        screen.Clear();
        screen.Sidebar(ScanShell.SidebarInfo());

        int left = screen.ContentLeft;
        int width = screen.ContentWidth;
        int y = screen.ContentTop;

        screen.Put(left, y++, "BEFORE THE SCAN STARTS", Tone.Title);
        screen.Rule(left, y++, width);
        y++;
        screen.Box(left, y, width, warning);
        y += warning.Count + 3;

        screen.Put(left, y++, "Mode: " + plan.Name, Tone.Dim);
        screen.Put(left, y++, "Layers: " + Screen.Clip(options.LayerSummary(), width - 8), Tone.Dim);

        screen.Put(left, screen.ContentBottom,
                   "[ENTER] scan anyway    [S] open settings    [0] cancel", Tone.Info);
        screen.Flush(true);

        while (true)
        {
            var key = screen.WaitKey();
            if (key.Key == ConsoleKey.Enter) return true;
            if (key.Key is ConsoleKey.Escape or ConsoleKey.D0 or ConsoleKey.NumPad0) return false;
            if (key.Key == ConsoleKey.S)
            {
                SettingsShell.Run(options);
                return Confirm(screen, ScanOptions.Load(), plan);
            }
        }
    }

    private static void ShowQuarantine(Screen screen)
    {
        if (!Elevation.IsAdministrator)
        {
            TextPager.Show(screen, "QUARANTINE", new[]
            {
                "The quarantine store lives under %ProgramData%\\Malward and a standard",
                "console cannot read it.",
                "",
                "Start the console as administrator and open this screen again,",
                "or use:  malcsm /quarmng /s",
            });
            return;
        }

        TextPager.Show(screen, "QUARANTINE", Capture(() => QuarantineShell.Run(
            new CommandLine(new[] { "/s" }))));
    }

    private static void ShowExclusions(Screen screen)
    {
        string message = "";
        while (true)
        {
            var lines = Capture(() => ExclusionShell.Run(new CommandLine(new[] { "/ev" }))).ToList();
            lines.Add("");
            lines.Add("[A] add a path    [R] remove by ID    [ENTER] back");
            if (message.Length > 0) { lines.Add(""); lines.Add(message); }
            message = "";

            var key = TextPager.Show(screen, "EXCLUSIONS", lines, allowKeys: true);
            if (key.Key == ConsoleKey.A)
            {
                var path = TextPager.Ask(screen, "Path to exclude: ");
                if (path is { Length: > 0 })
                    message = string.Join(" ", Capture(() => ExclusionShell.Run(
                        new CommandLine(new[] { "/ea", path }))));
                continue;
            }
            if (key.Key == ConsoleKey.R)
            {
                var id = TextPager.Ask(screen, "ID to remove: ");
                if (id is { Length: > 0 })
                    message = string.Join(" ", Capture(() => ExclusionShell.Run(
                        new CommandLine(new[] { "/er", id }))));
                continue;
            }
            return;
        }
    }

    private static void ShowDatabases(Screen screen)
    {
        var lines = new List<string>();
        var assembly = System.Reflection.Assembly.GetExecutingAssembly();
        lines.Add("Program version : " + (assembly.GetName().Version?.ToString() ?? "unknown"));
        lines.Add("Data folder     : " + Paths.DataDir);
        lines.Add("Elevated        : " + (Elevation.IsAdministrator ? "yes" : "no"));
        lines.Add("");
        lines.Add("DATABASE".PadRight(26) + "BUILD".PadRight(22) + "UPDATED");
        lines.Add(new string('-', 60));

        bool any = false;
        foreach (var entry in DatabaseInfo.Listed)
        {
            if (!DatabaseInfo.Installed(entry)) continue;
            any = true;
            var build = DatabaseInfo.Version(entry.VersionKey);
            lines.Add(entry.Name.PadRight(26)
                      + (build.Length == 0 ? "unknown" : build).PadRight(22)
                      + DatabaseInfo.BuildDate(entry));
        }
        if (!any)
        {
            lines.Add("none installed");
            lines.Add("");
            lines.Add("Run \"Check for updates\" from the main menu.");
        }

        TextPager.Show(screen, "DATABASES", lines);
    }

    private static IReadOnlyList<string> Capture(Func<int> action)
    {
        var writer = new StringWriter();
        try
        {
            using (ConsoleRouter.Scope(writer))
            using (new ErrorScope(writer))
                action();
        }
        catch (Exception ex) { writer.WriteLine("[!] " + ex.Message); }

        return writer.ToString()
                     .Replace("\r\n", "\n")
                     .Split('\n')
                     .Select(l => l.TrimEnd())
                     .ToList();
    }

    private static int Draw(Screen screen, ScanOptions options, string message)
    {
        screen.Sync();
        screen.Clear();
        screen.Sidebar(ScanShell.SidebarInfo());

        int left = screen.ContentLeft;
        int width = screen.ContentWidth;
        int bottom = screen.ContentBottom;
        int y = screen.ContentTop;

        screen.Put(left, y++, "MAIN MENU", Tone.Title);
        screen.Rule(left, y++, width);
        y++;

        foreach (var (key, label, hint) in Entries)
        {
            screen.Put(left, y, " " + key + ". ", Tone.Dim);
            screen.Put(left + 5, y, label.PadRight(22), Tone.Info);
            screen.Put(left + 27, y, Screen.Clip(hint, width - 28), Tone.Dim);
            y++;
        }

        y++;
        screen.Rule(left, y++, width);
        screen.Put(left, y++, Screen.Clip("Layers: " + options.LayerSummary(), width), Tone.Dim);
        screen.Put(left, y++, Screen.Clip("Action on a threat: " + options.FixLabel
            + (options.Fix != FixMode.Report && !Elevation.IsAdministrator
                ? "   (not elevated - the scan will only report)" : ""), width), Tone.Dim);
        y++;

        var warning = ScanShell.BuildWarning(options);
        if (warning != null && bottom - y > warning.Count + 3)
            screen.Box(left, y, width, warning);

        if (message.Length > 0)
            screen.Put(left, bottom - 2, Screen.Clip(message, width), Tone.Warn);

        int prompt = bottom - 1;
        screen.Put(left, prompt, "Your choice:", Tone.Info);
        screen.Put(left, bottom, "Ctrl+C is blocked while a task is running - use [Q] to stop a scan",
                   Tone.Dim);
        screen.Flush();
        return prompt;
    }
}

public static class TextPager
{
    public static ConsoleKeyInfo Show(Screen screen, string title,
                                      IReadOnlyList<string> lines, bool allowKeys = false)
    {
        int offset = 0;
        while (true)
        {
            screen.Sync();
            screen.Clear();
            screen.Sidebar(ScanShell.SidebarInfo());

            int left = screen.ContentLeft;
            int width = screen.ContentWidth;
            int bottom = screen.ContentBottom;
            int y = screen.ContentTop;

            screen.Put(left, y++, title, Tone.Title);
            screen.Rule(left, y++, width);

            int rows = bottom - 2 - y;
            offset = Math.Clamp(offset, 0, Math.Max(0, lines.Count - rows));
            for (int i = 0; i < rows; i++)
            {
                int index = offset + i;
                if (index >= lines.Count) break;
                screen.Put(left, y + i, Screen.Clip(lines[index], width));
            }

            screen.Rule(left, bottom - 1, width);
            string footer = lines.Count > rows
                ? $"[PgUp]/[PgDn] scroll  {offset + 1}-{Math.Min(lines.Count, offset + rows)}"
                  + $" of {lines.Count}   [ENTER] back"
                : "[ENTER] back";
            screen.Put(left, bottom, footer, Tone.Dim);
            screen.Flush();

            var key = screen.WaitKey();
            switch (key.Key)
            {
                case ConsoleKey.PageDown: offset += rows; break;
                case ConsoleKey.PageUp: offset -= rows; break;
                case ConsoleKey.DownArrow: offset++; break;
                case ConsoleKey.UpArrow: offset--; break;
                case ConsoleKey.Home: offset = 0; break;
                case ConsoleKey.End: offset = lines.Count; break;
                case ConsoleKey.Enter:
                case ConsoleKey.Escape:
                    return key;
                default:
                    if (allowKeys) return key;
                    break;
            }
        }
    }

    public static string? Ask(Screen screen, string label)
    {
        int left = screen.ContentLeft;
        int row = screen.ContentBottom - 1;
        screen.Put(left, row, new string(' ', screen.ContentWidth));
        screen.Put(left, row, label, Tone.Info);
        screen.Flush();
        var typed = screen.ReadLine(left + label.Length, row, screen.ContentWidth - label.Length);
        return typed?.Trim();
    }
}
