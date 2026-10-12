using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;

namespace Malward.AppGUI;

public static class PopupStackManager
{
    private static readonly object _lock = new();
    private static readonly List<Form> _stack = new();
    private const int Margin = 12;
    private const int Gap    = 8;

    public static void Register(Form f)
    {
        lock (_lock) { if (!_stack.Contains(f)) _stack.Add(f); Reflow(); }
    }

    public static void Unregister(Form f)
    {
        lock (_lock) { _stack.Remove(f); Reflow(); }
    }

    private static void Reflow()
    {
        Rectangle wa;
        try { wa = Screen.PrimaryScreen?.WorkingArea ?? new Rectangle(0, 0, 1920, 1080); }
        catch { return; }

        int y = wa.Bottom - Margin;

        for (int i = _stack.Count - 1; i >= 0; i--)
        {
            var f = _stack[i];
            if (f.IsDisposed) { _stack.RemoveAt(i); continue; }
            y -= f.Height;
            int x = wa.Right - f.Width - Margin;
            try { if (f.Location != new Point(x, y)) f.Location = new Point(x, y); } catch { }
            y -= Gap;
        }
    }
}
