using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;
using Malward.AppGUI.Services;

namespace Malward.AppGUI;

public interface IShieldPopupHost
{
    void AddOrUpdateBanner(string key, string text, Action onShow);

    void RegisterChild(Form child);

    Rectangle HostBounds { get; }
}

public static class ShieldPopupHub
{
    private static IShieldPopupHost? _host;

    public static IShieldPopupHost? Host =>
        _host is Form { IsDisposed: false, Disposing: false } ? _host : null;

    public static void SetHost(IShieldPopupHost host) => _host = host;

    public static void ClearHost(IShieldPopupHost host)
    {
        if (ReferenceEquals(_host, host)) _host = null;
    }

    public static bool Report(string key, string bannerText, Func<Form> makeWindow)
    {
        var h = Host;
        if (h == null) return false;
        try
        {
            h.AddOrUpdateBanner(key, bannerText, () =>
            {
                var w = makeWindow();
                h.RegisterChild(w);

                var b = h.HostBounds;
                w.StartPosition = FormStartPosition.Manual;
                w.Location = new Point(b.Right - w.Width, b.Bottom + 8);
                w.Show();
            });
            return true;
        }
        catch { return false; }
    }
}

public sealed class BannerStrip : Panel
{
    private const int H = 26;

    private sealed class Entry
    {
        public required string Key { get; init; }
        public required Panel Panel { get; init; }
        public required Label Label { get; init; }
        public required string Text { get; init; }
        public int Count { get; set; } = 1;
    }

    private readonly List<Entry> _entries = new();
    private readonly Action _onResize;

    private const int MaxWidocznych = 4;

    public BannerStrip(Action onResize)
    {
        _onResize = onResize;
        Dock = DockStyle.Top;
        Height = 0;
        BackColor = Color.FromArgb(0xFF, 0xF3, 0xCD);
    }

    public void AddOrUpdate(string key, string text, Action onShow)
    {
        var istniejacy = _entries.FirstOrDefault(w => w.Key == key);
        if (istniejacy != null)
        {
            istniejacy.Count++;
            istniejacy.Label.Text = Tekst(istniejacy.Text, istniejacy.Count);
            return;
        }
        if (_entries.Count >= MaxWidocznych) return;

        var pasek = new Panel { Dock = DockStyle.Top, Height = H, BackColor = Color.FromArgb(0xFF, 0xF3, 0xCD) };
        var lbl = new Label
        {
            Text = Tekst(text, 1), ForeColor = Color.FromArgb(0x5B, 0x45, 0x00), AutoSize = false,
            Location = new Point(10, 0), Size = new Size(Math.Max(80, Width - 110), H),
            TextAlign = ContentAlignment.MiddleLeft, Font = new Font("Segoe UI", 8.5f),
            AutoEllipsis = true, BackColor = Color.Transparent,
        };
        var link = new LinkLabel
        {
            Text = Loc.T("Wyświetl…"), AutoSize = false, Anchor = AnchorStyles.Top | AnchorStyles.Right,
            Location = new Point(Math.Max(90, Width - 96), 0), Size = new Size(86, H),
            TextAlign = ContentAlignment.MiddleRight, Font = new Font("Segoe UI", 8.5f),
            LinkColor = Color.FromArgb(0x8A, 0x66, 0x00), BackColor = Color.Transparent,
        };
        link.LinkClicked += (_, __) => { try { onShow(); } catch { } };
        pasek.Controls.Add(link);
        pasek.Controls.Add(lbl);
        pasek.Resize += (_, __) =>
        {
            lbl.Size = new Size(Math.Max(80, pasek.Width - 110), H);
            link.Location = new Point(Math.Max(90, pasek.Width - 96), 0);
        };

        Controls.Add(pasek);
        _entries.Add(new Entry { Key = key, Panel = pasek, Label = lbl, Text = text });
        Height = _entries.Count * H;
        _onResize();
    }

    private static string Tekst(string t, int n) =>
        "⚠  " + t + (n > 1 ? $"  ({n} działania)" : "");
}
