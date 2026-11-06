using System.Runtime.InteropServices;

namespace Malward.ConsoleShell;

public enum Tone
{
    Plain,
    Dim,
    Info,
    Warn,
    Heuristic,
    Threat,
    Title,
}

public static class Con
{
    private static bool? _colors;

    public static bool Colors
    {
        get
        {
            if (_colors.HasValue) return _colors.Value;
            bool on;
            try
            {
                on = !Console.IsOutputRedirected
                     && Environment.GetEnvironmentVariable("NO_COLOR") == null
                     && !string.Equals(Environment.GetEnvironmentVariable("TERM"), "dumb",
                                       StringComparison.OrdinalIgnoreCase);
            }
            catch { on = false; }
            _colors = on;
            return on;
        }
    }

    public static ConsoleColor ColorOf(Tone tone) => tone switch
    {
        Tone.Dim       => ConsoleColor.DarkGray,
        Tone.Info      => ConsoleColor.Cyan,
        Tone.Warn      => ConsoleColor.Yellow,
        Tone.Heuristic => ConsoleColor.DarkYellow,
        Tone.Threat    => ConsoleColor.Red,
        Tone.Title     => ConsoleColor.White,
        _              => ConsoleColor.Gray,
    };

    public static void Write(TextWriter output, string text, Tone tone)
    {
        if (!Colors || tone == Tone.Plain) { output.Write(text); return; }

        var previous = Console.ForegroundColor;
        try
        {
            Console.ForegroundColor = ColorOf(tone);
            output.Write(text);
        }
        finally { try { Console.ForegroundColor = previous; } catch { } }
    }

    public static void Line(string text = "", Tone tone = Tone.Plain)
    {
        Write(Console.Out, text, tone);
        Console.Out.Write(Environment.NewLine);
    }

    public static void ErrorLine(string text, Tone tone = Tone.Warn)
    {
        Write(Console.Error, text, tone);
        Console.Error.Write(Environment.NewLine);
    }

    public static void Clear()
    {
        if (Console.IsOutputRedirected) return;
        try { Console.Clear(); } catch { }
    }

    public const string ProductLine = "Malward(R) Cloud AntiVirus Scanner";
    public const string ToolLine = "Command Shell Manager";

    public static void Banner(string subtitle)
    {
        Clear();
        Line(ProductLine, Tone.Title);
        Line(ToolLine, Tone.Title);
        Line(new string('-', 54), Tone.Dim);
        if (subtitle.Length > 0) Line(subtitle, Tone.Dim);
        Line();
    }

    private const char TopLeft = '\u250c', TopRight = '\u2510', TopTee = '\u252c';
    private const char MidLeft = '\u251c', MidRight = '\u2524', MidCross = '\u253c';
    private const char LowLeft = '\u2514', LowRight = '\u2518', LowTee = '\u2534';
    private const char Horizontal = '\u2500', Vertical = '\u2502';

    /// <summary>A framed table. The last column takes whatever width is left and is cut to fit,
    /// so a long path never wraps the frame.</summary>
    public static void Table(IReadOnlyList<string> headers,
                             IReadOnlyList<IReadOnlyList<string>> rows,
                             IReadOnlyList<Tone> rowTones)
    {
        var widths = Widths(headers, rows);

        Rule(widths, TopLeft, TopTee, TopRight);
        Row(widths, headers, Tone.Dim);
        Rule(widths, MidLeft, MidCross, MidRight);
        for (int r = 0; r < rows.Count; r++)
            Row(widths, rows[r], r < rowTones.Count ? rowTones[r] : Tone.Plain);
        Rule(widths, LowLeft, LowTee, LowRight);
    }

    /// <summary>The same frame as <see cref="Table"/>, but as finished lines for a block that is
    /// redrawn in place. A row carries one tone, since the line is written in one go.</summary>
    public static List<(string Text, Tone Tone)> TableLines(IReadOnlyList<string> headers,
                                                            IReadOnlyList<IReadOnlyList<string>> rows,
                                                            IReadOnlyList<Tone> rowTones)
    {
        var widths = Widths(headers, rows);
        var lines = new List<(string, Tone)>
        {
            (RuleText(widths, TopLeft, TopTee, TopRight), Tone.Dim),
            (RowText(widths, headers), Tone.Dim),
            (RuleText(widths, MidLeft, MidCross, MidRight), Tone.Dim),
        };
        for (int r = 0; r < rows.Count; r++)
            lines.Add((RowText(widths, rows[r]), r < rowTones.Count ? rowTones[r] : Tone.Plain));
        lines.Add((RuleText(widths, LowLeft, LowTee, LowRight), Tone.Dim));
        return lines;
    }

    private static int[] Widths(IReadOnlyList<string> headers,
                                IReadOnlyList<IReadOnlyList<string>> rows)
    {
        int columns = headers.Count;
        var widths = new int[columns];
        for (int i = 0; i < columns; i++) widths[i] = headers[i].Length;
        foreach (var row in rows)
            for (int i = 0; i < columns; i++)
                widths[i] = Math.Max(widths[i], row[i].Length);

        int budget;
        try { budget = Console.IsOutputRedirected ? 200 : Math.Max(40, Console.WindowWidth - 1); }
        catch { budget = 200; }

        int overhead = 3 * columns + 1;
        int total = widths.Sum() + overhead;
        if (total > budget)
        {
            int last = columns - 1;
            widths[last] = Math.Max(16, widths[last] - (total - budget));
            total = widths.Sum() + overhead;
            for (int i = 0; i < last && total > budget; i++)
            {
                int cut = Math.Min(widths[i] - Math.Min(widths[i], 10), total - budget);
                widths[i] -= cut;
                total -= cut;
            }
        }
        return widths;
    }

    private static string RuleText(int[] widths, char left, char tee, char right)
    {
        var text = new System.Text.StringBuilder();
        text.Append(left);
        for (int i = 0; i < widths.Length; i++)
        {
            text.Append(new string(Horizontal, widths[i] + 2));
            text.Append(i == widths.Length - 1 ? right : tee);
        }
        return text.ToString();
    }

    private static string RowText(int[] widths, IReadOnlyList<string> cells)
    {
        var text = new System.Text.StringBuilder();
        for (int i = 0; i < widths.Length; i++)
        {
            text.Append(Vertical).Append(' ');
            text.Append(Clip(cells[i], widths[i]).PadRight(widths[i])).Append(' ');
        }
        return text.Append(Vertical).ToString();
    }

    private static void Rule(int[] widths, char left, char tee, char right)
        => Line(RuleText(widths, left, tee, right), Tone.Dim);

    private static void Row(int[] widths, IReadOnlyList<string> cells, Tone tone)
    {
        for (int i = 0; i < widths.Length; i++)
        {
            Write(Console.Out, Vertical + " ", Tone.Dim);
            Write(Console.Out, Clip(cells[i], widths[i]).PadRight(widths[i]) + " ", tone);
        }
        Write(Console.Out, Vertical.ToString(), Tone.Dim);
        Console.Out.Write(Environment.NewLine);
    }

    private static string Clip(string text, int width)
        => text.Length <= width ? text : text[..Math.Max(1, width - 1)] + "\u2026";

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetConsoleProcessList(uint[] processList, uint count);

    /// <summary>True when this process is the only one attached to the console window, which means
    /// the window was opened for it and would vanish with it - started from Explorer rather than
    /// typed at an existing prompt.</summary>
    public static bool OwnsConsoleWindow()
    {
        try
        {
            if (Console.IsOutputRedirected || Console.IsInputRedirected) return false;
            var buffer = new uint[8];
            uint n = GetConsoleProcessList(buffer, (uint)buffer.Length);
            return n == 1;
        }
        catch { return false; }
    }

    public static void HoldWindow()
    {
        if (!OwnsConsoleWindow()) return;
        Line();
        Line("Press any key to close this window...", Tone.Dim);
        try { Console.ReadKey(true); } catch { }
    }
}
