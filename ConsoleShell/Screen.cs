using System.Text;

namespace Malward.ConsoleShell;

public sealed record SidebarInfo(string Version, string Vps, string Updated);

public sealed class Screen
{
    private static readonly bool Ascii = ConsoleWindow.LegacyConsole;
    private static readonly char GlyphH  = Ascii ? '-' : '\u2500';
    private static readonly char GlyphV  = Ascii ? '|' : '\u2502';
    private static readonly char GlyphTL = Ascii ? '+' : '\u250C';
    private static readonly char GlyphTR = Ascii ? '+' : '\u2510';
    private static readonly char GlyphBL = Ascii ? '+' : '\u2514';
    private static readonly char GlyphBR = Ascii ? '+' : '\u2518';

    private const int SidebarGap = 2;
    private const int SidebarMinimumTotal = 98;

    private static readonly string[] Sgr =
    {
        "\u001b[37m",
        "\u001b[90m",
        "\u001b[96m",
        "\u001b[93m",
        "\u001b[33m",
        "\u001b[91m",
        "\u001b[97m",
    };

    private char[] _chars = Array.Empty<char>();
    private byte[] _tones = Array.Empty<byte>();
    private char[] _shownChars = Array.Empty<char>();
    private byte[] _shownTones = Array.Empty<byte>();

    private bool _full = true;
    private int _cursorRow = -1;
    private int _cursorColumn = -1;
    private int _anchor = -1;
    private bool _resized;
    private long _lastMeasure;
    private long _settleUntil;
    private long _lastForced;

    private readonly TextWriter _out;
    private readonly bool _vt;
    private readonly StringBuilder _frame = new(16384);

    public Screen()
    {
        _out = ConsoleWindow.Out;
        Live = !Console.IsOutputRedirected;
        _vt = Live && ConsoleWindow.VirtualTerminal;
        _settleUntil = Environment.TickCount64 + 2500;
        Measure(true);
    }

    public bool Live { get; }

    public TextWriter Output => _out;

    public int Width { get; private set; }
    public int Height { get; private set; }

    public bool HasSidebar { get; private set; }
    public int DividerColumn { get; private set; }

    public int ContentLeft { get; private set; }
    public int ContentTop { get; private set; }
    public int ContentWidth { get; private set; }
    public int ContentHeight { get; private set; }

    public int ContentBottom => ContentTop + ContentHeight - 1;

    public bool Sync()
    {
        int before = Width * 10000 + Height + _anchor * 1000000;
        Measure(false);
        if (before == Width * 10000 + Height + _anchor * 1000000) return false;
        _full = true;
        return true;
    }

    private void Measure(bool force)
    {
        int width = 118, height = 40;
        if (Live)
        {
            long now = Environment.TickCount64;
            if (!force && now - _lastMeasure < 300) return;
            _lastMeasure = now;

            ConsoleWindow.KeepSize();

            try
            {
                width = Math.Max(40, Console.WindowWidth);
                height = Math.Max(12, Console.WindowHeight);
                if (_vt) _anchor = 0;
                else if (_anchor < 0 || width != Width + 1 || height != Height)
                    _anchor = Math.Max(0, Console.WindowTop);
            }
            catch { }
        }

        Width = width - 1;
        Height = height;

        // Logo z gradientu ASCII i ramka obok niego wygladaja na starej konsoli jak smiec,
        // wiec tam zostaje sama tresc na pelnej szerokosci.
        HasSidebar = Width >= SidebarMinimumTotal && !Ascii;
        DividerColumn = HasSidebar ? AsciiArt.Width + SidebarGap : -1;
        ContentLeft = HasSidebar ? DividerColumn + SidebarGap : 2;
        ContentTop = 1;
        ContentWidth = Math.Max(20, Width - ContentLeft - 1);
        ContentHeight = Math.Max(6, Height - 2);

        int cells = Width * Height;
        if (_chars.Length != 0 && _chars.Length != cells) _resized = true;
        if (_chars.Length != cells)
        {
            _chars = new char[cells];
            _tones = new byte[cells];
            _shownChars = new char[cells];
            _shownTones = new byte[cells];
            for (int i = 0; i < cells; i++) _shownChars[i] = '\0';
            _full = true;
        }
    }

    public void Clear()
    {
        Array.Fill(_chars, ' ');
        Array.Fill(_tones, (byte)Tone.Plain);
    }

    public void Put(int x, int y, string? text, Tone tone = Tone.Plain)
    {
        if (text == null || y < 0 || y >= Height) return;
        int row = y * Width;
        for (int i = 0; i < text.Length; i++)
        {
            int column = x + i;
            if (column < 0) continue;
            if (column >= Width) break;
            char c = text[i];
            if (c == '\t') c = ' ';
            _chars[row + column] = Plain(c);
            _tones[row + column] = (byte)tone;
        }
    }

    public void Put(int x, int y, char value, Tone tone)
    {
        if (y < 0 || y >= Height || x < 0 || x >= Width) return;
        int cell = y * Width + x;
        _chars[cell] = Plain(value);
        _tones[cell] = (byte)tone;
    }

    public void PutClipped(int x, int y, string? text, int width, Tone tone = Tone.Plain)
        => Put(x, y, Clip(text ?? "", width), tone);

    public void Rule(int x, int y, int width, Tone tone = Tone.Dim, char fill = '\0')
        => Put(x, y, new string(fill == '\0' ? GlyphH : fill, Math.Max(0, width)), tone);

    // Jedna tablica transliteracji dla calego programu - Con.Transliterate.
    private static char Plain(char value)
        => !Ascii || value <= '~' ? value : Con.Plain(value.ToString())[0];

    public static string Clip(string text, int width)
    {
        if (width <= 0) return "";
        if (text.Length <= width) return text;
        if (width <= 1) return text[..1];
        return text[..(width - 1)] + (Ascii ? "~" : "…");
    }

    public static string ClipLeft(string text, int width)
    {
        if (width <= 0) return "";
        if (text.Length <= width) return text;
        if (width <= 1) return text[^1..];
        return "…" + text[^(width - 1)..];
    }

    public static string ClipPath(string text, int width)
    {
        if (text.Length <= width) return text;
        return ClipLeft(text, width);
    }

    public void Field(int x, int y, string label, string value, int labelWidth,
                      Tone valueTone = Tone.Plain)
    {
        Put(x, y, label.PadRight(labelWidth), Tone.Dim);
        Put(x + labelWidth, y, value, valueTone);
    }

    public void Box(int x, int y, int width, IReadOnlyList<(string Text, Tone Tone)> lines,
                    Tone frame = Tone.Warn)
    {
        if (width < 8) return;
        int inner = width - 4;
        Put(x, y, GlyphTL + new string(GlyphH, width - 2) + GlyphTR, frame);
        for (int i = 0; i < lines.Count; i++)
        {
            int row = y + 1 + i;
            if (row >= Height) return;
            Put(x, row, GlyphV.ToString(), frame);
            Put(x + 2, row, Clip(lines[i].Text, inner), lines[i].Tone);
            Put(x + width - 1, row, GlyphV.ToString(), frame);
        }
        Put(x, y + lines.Count + 1, GlyphBL + new string(GlyphH, width - 2) + GlyphBR, frame);
    }

    private static Tone Ink(char value) => value switch
    {
        '@' or '%' => Tone.Title,
        '#' or '*' => Tone.Plain,
        _ => Tone.Dim,
    };

    public void Sidebar(SidebarInfo info)
    {
        if (!HasSidebar) return;

        var logo = Height >= 34 ? AsciiArt.Logo
                 : Height >= 24 ? AsciiArt.Compact
                 : Array.Empty<string>();

        int y = 0;
        foreach (var line in logo)
        {
            if (y >= Height - 4) break;
            for (int x = 0; x < line.Length && x < Width; x++)
                Put(x, y, line[x], Ink(line[x]));
            y++;
        }

        var rule = new string(GlyphH, 22);
        var block = new List<(string Text, Tone Tone, int Drop)>
        {
            ("", Tone.Plain, 3),
            (Con.ProductLine, Tone.Title, 0),
            (Con.ToolLine, Tone.Title, 0),
            ("", Tone.Plain, 3),
            ("Scan files on this PC to look up", Tone.Plain, 2),
            ("for hidden threats.", Tone.Plain, 2),
            ("", Tone.Plain, 3),
            ("Version: " + info.Version, Tone.Dim, 0),
            ("VPS: " + info.Vps, Tone.Dim, 0),
            (rule, Tone.Dim, 1),
            ("Last update: " + info.Updated, Tone.Dim, 0),
            (rule, Tone.Dim, 1),
            ("", Tone.Plain, 3),
            (Elevation.IsAdministrator ? "Running as administrator" : "Running as standard user",
             Elevation.IsAdministrator ? Tone.Info : Tone.Dim, 1),
        };

        int room = Height - 2 - y;
        for (int drop = 3; drop >= 1 && block.Count > room; drop--)
            block.RemoveAll(entry => entry.Drop == drop && block.Count > room);

        foreach (var (text, tone, _) in block)
        {
            if (y >= Height - 1) break;
            Put(0, y++, Clip(text, AsciiArt.Width), tone);
        }

        if (Height >= 3) Put(0, Height - 2, "jmsoft.pl", Tone.Info);

        for (int row = 0; row < Height; row++)
            Put(DividerColumn, row, GlyphV.ToString(), Tone.Dim);
    }

    public void Flush(bool force = false)
    {
        if (!Live) return;
        bool full = _full || force;
        _full = false;

        if (_resized)
        {
            _resized = false;
            full = true;
            if (_vt) _frame.Append("\u001b[2J");
            else
            {
                try { Console.Clear(); _anchor = Math.Max(0, Console.WindowTop); } catch { }
            }
            _cursorRow = -1;
            _cursorColumn = -1;
        }

        if (_vt) FlushVirtualTerminal(full);
        else FlushLegacy(full);
    }

    private bool RowChanged(int row)
    {
        for (int x = 0; x < Width; x++)
            if (_chars[row + x] != _shownChars[row + x] || _tones[row + x] != _shownTones[row + x])
                return true;
        return false;
    }

    private void FlushVirtualTerminal(bool full)
    {
        _frame.Append("\u001b[?25l");
        int tone = -1;
        bool wrote = false;

        for (int y = 0; y < Height; y++)
        {
            int row = y * Width;
            if (!full && !RowChanged(row)) continue;

            _frame.Append("\u001b[").Append(y + 1).Append(";1H");
            int column = 0;
            while (column < Width)
            {
                int start = column;
                byte run = _tones[row + column];
                while (column < Width && _tones[row + column] == run) column++;
                if (run != tone)
                {
                    tone = run;
                    _frame.Append(Sgr[run < Sgr.Length ? run : 0]);
                }
                _frame.Append(_chars, row + start, column - start);
            }
            wrote = true;

            Array.Copy(_chars, row, _shownChars, row, Width);
            Array.Copy(_tones, row, _shownTones, row, Width);
        }

        if (!wrote && _frame.Length <= "\u001b[?25l".Length) { _frame.Clear(); return; }

        _frame.Append("\u001b[0m\u001b[").Append(Height).Append(";1H");
        _cursorRow = Height - 1;
        _cursorColumn = 0;

        try { _out.Write(_frame.ToString()); }
        catch { }
        _frame.Clear();
    }

    private void FlushLegacy(bool full)
    {
        try { Console.CursorVisible = false; } catch { }

        for (int y = 0; y < Height; y++)
        {
            int row = y * Width;
            if (!full && !RowChanged(row)) continue;

            int column = 0;
            while (column < Width)
            {
                int start = column;
                byte tone = _tones[row + column];
                while (column < Width && _tones[row + column] == tone) column++;
                if (!Place(start, y)) break;
                Con.Write(_out, new string(_chars, row + start, column - start), (Tone)tone);
                _cursorColumn = column;
            }

            Array.Copy(_chars, row, _shownChars, row, Width);
            Array.Copy(_tones, row, _shownTones, row, Width);
        }

        Place(0, Height - 1);
    }

    private bool Place(int x, int y)
    {
        if (_cursorRow == y && _cursorColumn == x) return true;
        if (_vt)
        {
            try { _out.Write("\u001b[" + (y + 1) + ";" + (x + 1) + "H"); }
            catch { return false; }
            _cursorRow = y;
            _cursorColumn = x;
            return true;
        }
        try
        {
            Console.SetCursorPosition(x, _anchor + y);
            _cursorRow = y;
            _cursorColumn = x;
            return true;
        }
        catch { return false; }
    }

    private void ShowCursor(bool visible)
    {
        if (_vt)
        {
            try { _out.Write(visible ? "\u001b[?25h" : "\u001b[?25l"); } catch { }
            return;
        }
        try { Console.CursorVisible = visible; } catch { }
    }

    public void Invalidate() => _full = true;

    public string? ReadLine(int x, int y, int maxLength, string seed = "")
    {
        if (!Live || Console.IsInputRedirected)
        {
            try { return Console.ReadLine(); }
            catch { return null; }
        }

        var text = new StringBuilder(seed);
        maxLength = Math.Max(1, Math.Min(maxLength, Width - x - 1));

        while (true)
        {
            _cursorRow = -1;
            Place(x, y);
            if (_vt) { try { _out.Write(Sgr[(int)Tone.Title] + text.ToString().PadRight(maxLength) + "[0m"); } catch { } }
            else Con.Write(_out, text.ToString().PadRight(maxLength), Tone.Title);
            _cursorColumn = x + maxLength;
            Place(x + Math.Min(text.Length, maxLength - 1), y);
            ShowCursor(true);

            var key = NextKey();

            if (key.Key == ConsoleKey.Enter)
            {
                ShowCursor(false);
                MarkDirty(x, y, maxLength);
                return text.ToString().Trim();
            }
            if (key.Key == ConsoleKey.Escape)
            {
                ShowCursor(false);
                MarkDirty(x, y, maxLength);
                return null;
            }
            if (key.Key == ConsoleKey.Backspace)
            {
                if (text.Length > 0) text.Length--;
                continue;
            }
            if (key.KeyChar >= ' ' && text.Length < maxLength - 1) text.Append(key.KeyChar);
        }
    }

    private void MarkDirty(int x, int y, int width)
    {
        int row = y * Width;
        for (int i = 0; i < width && x + i < Width; i++) _shownChars[row + x + i] = '\0';
    }

    public ConsoleKeyInfo WaitKey()
    {
        ShowCursor(false);
        return NextKey();
    }

    private ConsoleKeyInfo NextKey()
    {
        try
        {
            if (!Live || Console.IsInputRedirected) return Console.ReadKey(true);
        }
        catch { }

        while (true)
        {
            try
            {
                if (Console.KeyAvailable) return Console.ReadKey(true);
            }
            catch
            {
                try { return Console.ReadKey(true); }
                catch { return new ConsoleKeyInfo('\r', ConsoleKey.Enter, false, false, false); }
            }

            ConsoleWindow.KeepSize();
            long now = Environment.TickCount64;
            bool moved = Sync();
            if (moved || now < _settleUntil)
            {
                if (moved || now - _lastForced > 400)
                {
                    _lastForced = now;
                    Flush(true);
                }
            }
            Thread.Sleep(60);
        }
    }
}
