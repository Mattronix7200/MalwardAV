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

    // Ekrany pelnoekranowe sanityzuje Screen.Put, ale pomoc, lista wykluczen i
    // komunikaty startowe ida prosto tutaj. Bez tego na konsoli sprzed Windows 10
    // myslnik i wielokropek wychodza krzakami tak samo jak ramki.
    public static string Plain(string text)
    {
        if (!ConsoleWindow.LegacyConsole || text.Length == 0) return text;
        Span<char> buf = text.Length <= 512 ? stackalloc char[text.Length] : new char[text.Length];
        bool zmiana = false;
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            char p = c <= '\u007E' ? c : Transliterate(c);
            buf[i] = p;
            if (p != c) zmiana = true;
        }
        return zmiana ? new string(buf) : text;
    }

    private static char Transliterate(char value) => value switch
    {
        '\u2014' or '\u2013' or '\u2212' => '-',
        '\u2026' => '~',
        '\u2018' or '\u2019' or '\u201A' => '\'',
        '\u201C' or '\u201D' or '\u201E' => '"',
        '\u00A0' => ' ',
        '\u2022' or '\u00B7' => '*',
        '\u00D7' => 'x',
        '\u0105' => 'a', '\u0104' => 'A',
        '\u0107' => 'c', '\u0106' => 'C',
        '\u0119' => 'e', '\u0118' => 'E',
        '\u0142' => 'l', '\u0141' => 'L',
        '\u0144' => 'n', '\u0143' => 'N',
        '\u00F3' => 'o', '\u00D3' => 'O',
        '\u015B' => 's', '\u015A' => 'S',
        '\u017A' or '\u017C' => 'z',
        '\u0179' or '\u017B' => 'Z',
        _ => '?',
    };

    public static void Write(TextWriter output, string text, Tone tone)
    {
        text = Plain(text);
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

    public const string ProductLine = "Malward(R) Cloud Scanner Portable";
    public const string ToolLine = "Command Tool Utility";

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
