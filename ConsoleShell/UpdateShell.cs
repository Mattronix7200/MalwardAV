using System.Globalization;
using Malward.Engine.Config;
using Malward.Engine.Util;

namespace Malward.ConsoleShell;

public static class UpdateShell
{
    private static readonly (string Key, string Name)[] Components =
    {
        ("vps",       "Threat signatures"),
        ("heur",      "Heuristic rules"),
        ("whitelist", "Detection signatures"),
    };

    private sealed class Sink : TextWriter
    {
        private readonly List<string> _lines;
        private readonly System.Text.StringBuilder _buffer = new();

        public Sink(List<string> lines) => _lines = lines;

        public override System.Text.Encoding Encoding => System.Text.Encoding.UTF8;

        public override void Write(char value)
        {
            if (value == '\n') { Flush(); return; }
            if (value != '\r') lock (_buffer) _buffer.Append(value);
        }

        public override void Write(string? value)
        {
            if (value == null) return;
            foreach (var c in value) Write(c);
        }

        public override void Flush()
        {
            string text;
            lock (_buffer)
            {
                if (_buffer.Length == 0) return;
                text = _buffer.ToString().Trim();
                _buffer.Clear();
            }
            if (text.Length == 0) return;
            lock (_lines)
            {
                _lines.Add(text);
                if (_lines.Count > 500) _lines.RemoveAt(0);
            }
        }
    }

    public static int Run(bool interactive)
    {
        ConsoleWindow.Enter();

        var screen = new Screen();
        var settings = new Settings();
        var state = new Dictionary<string, (string Phase, double Pct)>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, _) in Components) state[key] = ("waiting", 0);

        var lines = new List<string>();
        string headline = "Contacting the update server...";
        var started = DateTime.Now;
        var gate = new object();
        var lastDraw = DateTime.MinValue;

        void Draw(bool force)
        {
            if (!Monitor.TryEnter(gate)) return;
            try
            {
                var now = DateTime.UtcNow;
                if (!force && now - lastDraw < TimeSpan.FromMilliseconds(120)) return;
                lastDraw = now;

                if (!screen.Live)
                {
                    screen.Output.WriteLine(headline);
                    return;
                }

                screen.Sync();
                screen.Clear();
                screen.Sidebar(ScanShell.SidebarInfo());

                int left = screen.ContentLeft;
                int width = screen.ContentWidth;
                int bottom = screen.ContentBottom;
                int y = screen.ContentTop;

                screen.Put(left, y++, "DATABASE UPDATE", Tone.Title);
                screen.Rule(left, y++, width);
                y++;

                screen.Put(left, y, "DATABASE".PadRight(28) + "STATUS", Tone.Dim);
                y++;
                screen.Rule(left, y++, width);

                double total = 0;
                foreach (var (key, name) in Components)
                {
                    var (phase, pct) = state[key];
                    total += phase is "updated" or "current" ? 1 : pct;
                    screen.Put(left, y, name.PadRight(28),
                               phase == "waiting" ? Tone.Dim : Tone.Plain);
                    screen.Put(left + 28, y, Describe(phase, pct),
                               phase == "waiting" ? Tone.Dim : Tone.Info);
                    y++;
                }

                screen.Rule(left, y++, width);
                screen.Field(left, y++, "Completed:",
                    (total / Components.Length * 100).ToString("F1", CultureInfo.InvariantCulture) + " %",
                    14, Tone.Info);
                screen.Field(left, y++, "Elapsed:",
                    (DateTime.Now - started).ToString("hh\\:mm\\:ss", CultureInfo.InvariantCulture), 14);
                y++;

                screen.Put(left, y++, Screen.Clip(headline, width), Tone.Plain);
                y++;

                string[] tail;
                lock (lines) tail = lines.Skip(Math.Max(0, lines.Count - (bottom - 2 - y))).ToArray();
                foreach (var line in tail)
                {
                    if (y > bottom - 2) break;
                    screen.Put(left, y++, Screen.Clip(line, width), Tone.Dim);
                }

                screen.Rule(left, bottom - 1, width);
                screen.Put(left, bottom,
                    headline.StartsWith("Done", StringComparison.Ordinal)
                    || headline.StartsWith("Update failed", StringComparison.Ordinal)
                        ? "[ENTER] continue"
                        : "Downloading - please wait", Tone.Info);
                screen.Flush();
            }
            finally { Monitor.Exit(gate); }
        }

        Draw(true);
        ConsoleWindow.Busy = true;
        int exit;

        try
        {
            using var sink = new Sink(lines);
            using var errors = new ErrorScope(sink);

            using var service = new Malward.Engine.Cloud.UpdateService(settings);
            service.Progress = (component, phase, pct) =>
            {
                if (!state.ContainsKey(component)) return;
                state[component] = (phase, pct);
                headline = $"{Name(component)}: {Describe(phase, pct)}";
                Draw(phase is "updated" or "current");
            };

            int refreshed;
            using (ConsoleRouter.Scope(sink))
                refreshed = service.UpdateAllAsync().GetAwaiter().GetResult();

            foreach (var (key, _) in Components)
                if (state[key].Phase is "waiting" or "checking" or "downloading")
                    state[key] = ("current", 1);

            headline = refreshed > 0
                ? $"Done - {refreshed} database(s) refreshed."
                : "Done - everything was already up to date.";
            exit = 0;
        }
        catch (Exception ex)
        {
            headline = "Update failed: " + ex.Message;
            exit = 6;
        }
        finally { ConsoleWindow.Busy = false; }

        Draw(true);

        if (!screen.Live) { screen.Output.WriteLine(headline); return exit; }
        try { if (!Console.IsInputRedirected) screen.WaitKey(); } catch { }
        return exit;
    }

    private static string Name(string key)
    {
        foreach (var (k, n) in Components) if (k == key) return n;
        return key;
    }

    private static string Describe(string phase, double pct) => phase switch
    {
        "waiting" => "waiting",
        "checking" => "checking",
        "downloading" => "downloading "
            + (pct * 100).ToString("F1", CultureInfo.InvariantCulture) + " %",
        "updated" => "updated",
        _ => "up to date",
    };
}
