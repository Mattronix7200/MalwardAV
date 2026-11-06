namespace Malward.ConsoleShell;

public readonly record struct StatusLine(string Text, Tone Tone)
{
    public static implicit operator StatusLine(string text) => new(text, Tone.Plain);
}

/// <summary>A block of lines redrawn in place. Falls back to plain appended output when the
/// console is redirected, so piping the scanner to a file still produces readable text.</summary>
public sealed class StatusBlock
{
    private readonly TextWriter _out;
    private readonly bool _live;
    private int _top = -1;
    private int _count;
    private DateTime _lastDraw = DateTime.MinValue;
    private string _lastPlain = "";

    public StatusBlock(TextWriter output)
    {
        _out = output;
        bool live;
        try { live = !Console.IsOutputRedirected && Console.WindowWidth > 0; }
        catch { live = false; }
        _live = live;
    }

    public TimeSpan MinInterval { get; set; } = TimeSpan.FromMilliseconds(120);

    public bool Live => _live;

    public void Render(IReadOnlyList<StatusLine> lines, bool force = false)
    {
        var now = DateTime.UtcNow;
        if (!force && now - _lastDraw < MinInterval) return;
        _lastDraw = now;

        if (!_live) { RenderPlain(lines); return; }

        try { RenderLive(lines); }
        catch { RenderPlain(lines); }
    }

    public void Release()
    {
        if (!_live) return;
        try
        {
            if (_top >= 0) Console.SetCursorPosition(0, Math.Min(Console.BufferHeight - 1, _top + _count));
            Console.CursorVisible = true;
        }
        catch { }
        _top = -1;
        _count = 0;
    }

    private void RenderLive(IReadOnlyList<StatusLine> lines)
    {
        int width = Math.Max(20, Console.WindowWidth - 1);

        int maxRows = Math.Max(4, Console.WindowHeight - 1);
        if (lines.Count > maxRows)
            lines = lines.Take(maxRows - 1).Append(lines[^1]).ToList();
        try { Console.CursorVisible = false; } catch { }

        if (_top >= 0)
        {
            int top = Math.Max(0, Math.Min(_top, Console.BufferHeight - 1));
            Console.SetCursorPosition(0, top);
        }

        int rows = Math.Max(lines.Count, _count);
        for (int i = 0; i < rows; i++)
        {
            var line = i < lines.Count ? lines[i] : default;
            Con.Write(_out, Fit(line.Text ?? "", width), line.Tone);
            _out.Write(Environment.NewLine);
        }

        _count = rows;
        _top = Math.Max(0, Console.CursorTop - rows);
    }

    private void RenderPlain(IReadOnlyList<StatusLine> lines)
    {
        var text = string.Join(" | ", lines
            .Select(l => l.Text ?? "")
            .Where(t => t.Length > 0 && t[0] != '_'));
        if (text == _lastPlain) return;
        _lastPlain = text;
        _out.Write(text);
        _out.Write(Environment.NewLine);
    }

    private static string Fit(string text, int width)
    {
        if (text.Length > width) return text[..Math.Max(0, width - 1)] + "…";
        return text.PadRight(width);
    }
}
