using System.Globalization;

namespace Malward.ConsoleShell;

public static class SettingsShell
{
    private sealed record Row(string State, string Label, bool Risky);

    private const int StateWidth = 17;

    public static void Run(ScanOptions options)
    {
        ConsoleWindow.Enter();
        var screen = new Screen();
        string message = "";

        while (true)
        {
            int prompt = Draw(screen, options, message);
            message = "";

            var input = screen.ReadLine(screen.ContentLeft + 13, prompt, 12);
            if (input == null) { options.Save(); return; }

            var choice = input.Trim().ToLowerInvariant();
            if (choice.Length == 0) continue;
            if (choice is "0" or "q" or "x") { options.Save(); return; }

            if (choice is "r" or "reset")
            {
                options.Reset();
                options.Save();
                message = "Defaults restored.";
                continue;
            }

            if (!int.TryParse(choice, NumberStyles.Integer, CultureInfo.InvariantCulture, out int number)
                || number < 1 || number > 17)
            {
                message = $"Unknown option: {input}. Type 1-17, R to restore defaults, 0 to go back.";
                continue;
            }

            message = Apply(screen, options, number, prompt);
            options.Clamp();
            if (!options.Save()) message = "Changed, but the settings file could not be written.";
        }
    }

    private static string Apply(Screen screen, ScanOptions options, int number, int prompt)
    {
        switch (number)
        {
            case 1: options.CloudScan = !options.CloudScan; break;
            case 2: options.CloudVerify = !options.CloudVerify; break;
            case 3: options.CloudCache = !options.CloudCache; break;
            case 4: options.SkipSigned = !options.SkipSigned; break;
            case 5: options.MemoryScan = !options.MemoryScan; break;
            case 6: options.Archives = !options.Archives; break;
            case 7: options.Heuristics = !options.Heuristics; break;

            case 8: return Number(screen, prompt, "parallel scanning threads", 1, 256,
                                  options.EffectiveThreads, v => options.Threads = v);
            case 9: return Number(screen, prompt, "processor budget in percent", 5, 100,
                                  options.CpuLimit, v => options.CpuLimit = v);
            case 10: return Size(screen, prompt, "largest file scanned in MB",
                                 options.MaxFileMb, v => options.MaxFileMb = v);
            case 11: return Number(screen, prompt, "seconds to wait for a cloud verdict", 5, 600,
                                   options.CloudWaitSec, v => options.CloudWaitSec = v);
            case 12: return Number(screen, prompt, "seconds of scan budget per file", 5, 3600,
                                   options.FileBudgetSec, v => options.FileBudgetSec = v);
            case 13: return Size(screen, prompt, "largest archive opened in MB",
                                 options.ArchiveMaxMb, v => options.ArchiveMaxMb = v);
            case 14: return Number(screen, prompt, "archive nesting depth", 0, 12,
                                   options.ArchiveDepth, v => options.ArchiveDepth = v);

            case 15:
                options.Fix = options.Fix switch
                {
                    FixMode.Report => FixMode.Quarantine,
                    FixMode.Quarantine => FixMode.Delete,
                    FixMode.Delete => FixMode.Ask,
                    _ => FixMode.Report,
                };
                if (options.Fix != FixMode.Report && !Elevation.IsAdministrator)
                    return "Repairing needs an elevated console; without it the scan only reports.";
                break;

            case 16:
                options.ArchiveFix = options.ArchiveFix == ArchiveFixMode.DropEntry
                    ? ArchiveFixMode.DeleteArchive : ArchiveFixMode.DropEntry;
                break;

            case 17:
                options.Extensions = options.Extensions switch
                {
                    ExtensionMode.All => ExtensionMode.Common,
                    _ => ExtensionMode.All,
                };
                options.ExtensionList.Clear();
                break;
        }

        if (number == 1 && !options.CloudScan)
            return "Cloud scanning is off - detections will not be confirmed.";
        if (number == 2 && !options.CloudVerify)
            return "Cloud verification is off - database hits go straight to the report.";
        if (number == 7 && options.Heuristics)
            return "Heuristics are on - expect more false positives.";
        return "";
    }

    private static string Number(Screen screen, int prompt, string what, int min, int max,
                                 int current, Action<int> set)
    {
        string label = $"{what} ({min}-{max}), now {current}: ";
        screen.Put(screen.ContentLeft, prompt, new string(' ', screen.ContentWidth));
        screen.Put(screen.ContentLeft, prompt, label, Tone.Info);
        screen.Flush();

        var input = screen.ReadLine(screen.ContentLeft + label.Length, prompt, 10);
        if (input == null || input.Length == 0) return "";
        if (!int.TryParse(input, NumberStyles.Integer, CultureInfo.InvariantCulture, out int value))
            return $"{input} is not a number.";
        if (value < min || value > max) return $"Value must be between {min} and {max}.";
        set(value);
        return "";
    }

    private static string Size(Screen screen, int prompt, string what, int current, Action<int> set)
    {
        string now = current >= ScanOptions.NoLimitMb ? "unlimited" : current.ToString(CultureInfo.InvariantCulture);
        string label = $"{what} (1-100000, 0 = unlimited), now {now}: ";
        screen.Put(screen.ContentLeft, prompt, new string(' ', screen.ContentWidth));
        screen.Put(screen.ContentLeft, prompt, label, Tone.Info);
        screen.Flush();

        var input = screen.ReadLine(screen.ContentLeft + label.Length, prompt, 10);
        if (input == null || input.Length == 0) return "";
        if (!int.TryParse(input, NumberStyles.Integer, CultureInfo.InvariantCulture, out int value))
            return $"{input} is not a number.";
        if (value < 0 || value > 100000) return "Value must be between 0 and 100000.";
        set(value == 0 ? ScanOptions.NoLimitMb : value);
        return "";
    }

    private static Row[] Rows(ScanOptions o) => new[]
    {
        new Row(State(o.CloudScan), "cloud scanning", !o.CloudScan),
        new Row(State(o.CloudVerify), "verify hits in the cloud", !o.CloudVerify),
        new Row(State(o.CloudCache), "skip what the cloud already knows", !o.CloudCache),
        new Row(State(o.SkipSigned), "skip Microsoft-signed system files", false),
        new Row(State(o.MemoryScan), "scan running processes", false),
        new Row(State(o.Archives), "look inside archives", false),
        new Row(State(o.Heuristics), "heuristic analysis", o.Heuristics),

        new Row($"[{o.EffectiveThreads}]", "parallel scanning threads", false),
        new Row($"[{o.CpuLimit}%]", "cap the processor budget", false),
        new Row($"[{ScanOptions.Limit(o.MaxFileMb)}]", "largest file scanned", false),
        new Row($"[{o.CloudWaitSec} s]", "wait for a cloud verdict", false),
        new Row($"[{o.FileBudgetSec} s]", "time budget per file", false),
        new Row($"[{ScanOptions.Limit(o.ArchiveMaxMb)}]", "largest archive opened", false),
        new Row($"[{o.ArchiveDepth}]", "archive nesting depth", false),

        new Row($"[{o.FixLabel}]", "action for threats in files", false),
        new Row($"[{o.ArchiveFixLabel}]", "action for threats inside archives", false),
        new Row($"[{o.ExtensionLabel}]", "scanned extensions", false),
    };

    private static string State(bool on) => on ? "[ENABLED]" : "[DISABLED]";

    private static readonly string[] HelpText =
    {
        "In lines 1-7 and 15-17 type the number and press ENTER to change the state.",
        "In lines 8-14 type the number, press ENTER, then type a value in the allowed",
        "range and press ENTER again.",
        "",
        "Turning 1, 2 or 3 off removes the cloud cross-check: a database hit is then",
        "reported with no second opinion, so clean files can be flagged as threats.",
        "Turning 7 on judges files by shape instead of by a known signature and also",
        "produces false positives - it works best with cloud scanning left on.",
        "Changing 8-14 can slow the machine down or cut scans short.",
    };

    private static int Draw(Screen screen, ScanOptions options, string message)
    {
        screen.Sync();
        screen.Clear();
        screen.Sidebar(ScanShell.SidebarInfo());

        int left = screen.ContentLeft;
        int width = screen.ContentWidth;
        int y = screen.ContentTop;
        int bottom = screen.ContentBottom;

        screen.Put(left, y++, "SETTINGS", Tone.Title);
        screen.Rule(left, y++, width);

        var rows = Rows(options);
        for (int i = 0; i < rows.Length && y <= bottom - 3; i++)
        {
            var row = rows[i];
            var number = (i + 1).ToString(CultureInfo.InvariantCulture).PadLeft(2);
            screen.Put(left, y, number + ". ", Tone.Dim);
            screen.Put(left + 4, y, Screen.Clip(row.State, StateWidth).PadRight(StateWidth),
                       row.State == "[DISABLED]" ? Tone.Dim : Tone.Info);
            screen.Put(left + 4 + StateWidth, y,
                       Screen.Clip(row.Label, width - 6 - StateWidth - 6));
            if (row.Risky) screen.Put(left + width - 5, y, "( ! )", Tone.Warn);
            y++;
        }

        screen.Rule(left, y++, width);
        foreach (var line in HelpText)
        {
            if (y > bottom - 3) break;
            screen.Put(left, y++, Screen.Clip(line, width), Tone.Dim);
        }

        if (message.Length > 0)
            screen.Put(left, bottom - 2, Screen.Clip(message, width), Tone.Warn);

        screen.Put(left, bottom, "[0] back   [R] restore defaults", Tone.Dim);

        int prompt = bottom - 1;
        screen.Put(left, prompt, "Your option:", Tone.Info);
        screen.Flush();
        return prompt;
    }
}
