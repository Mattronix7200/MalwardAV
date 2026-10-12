using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Windows.Forms;
using Malward.AppGUI.Services;

namespace Malward.AppGUI;

public sealed class HipsAlertForm : Form
{
    private const int W = 460;

    public sealed record Info(string RuleName, string Detail, string Where, string Process,
                              string Kind, bool Blocked);

    private sealed record Item(Info Info, Action? OnFix, Action? OnAllow);

    private readonly bool _decide;
    protected override bool ShowWithoutActivation => !_decide;

    private readonly Color _border, _fg, _sub, _bg, _box;
    private readonly List<Item> _items = new();
    private int _idx;

    private readonly Label _lblRule, _lblDetail, _lblWhereK, _lblWhereV, _lblProcV;
    private Label? _lblPager;
    private Button? _btnPrev, _btnNext;
    private readonly Action? _onDetails;

    private static HipsAlertForm? _live;
    public static HipsAlertForm? Live =>
        _live is { IsDisposed: false, Disposing: false, _decide: true } f ? f : null;

    public HipsAlertForm(bool dark, Info info, byte[]? hipsIcon, byte[]? logoIcon, Icon? appIcon,
                         Action? onFix, Action? onAllow, Action? onDetails)
    {
        _decide = onFix != null || onAllow != null;
        _onDetails = onDetails;
        _items.Add(new Item(info, onFix, onAllow));

        _bg     = dark ? Color.FromArgb(0x16, 0x1B, 0x22) : Color.White;
        _fg     = dark ? Color.FromArgb(0xE9, 0xEC, 0xF0) : Color.FromArgb(0x0E, 0x11, 0x16);
        _sub    = dark ? Color.FromArgb(0x9C, 0xA3, 0xAF) : Color.FromArgb(0x55, 0x5C, 0x66);
        _border = dark ? Color.FromArgb(0x2B, 0x33, 0x3E) : Color.FromArgb(0xC9, 0xCF, 0xD6);
        _box    = dark ? Color.FromArgb(0x1C, 0x23, 0x2C) : Color.FromArgb(0xF6, 0xF8, 0xFA);

        Color head = info.Blocked ? Color.FromArgb(0xC0, 0x2A, 0x2A) : Color.FromArgb(0xB5, 0x7A, 0x1B);

        FormBorderStyle = FormBorderStyle.None;
        ShowInTaskbar   = false;
        TopMost         = true;
        StartPosition   = FormStartPosition.Manual;
        BackColor       = _bg;
        Width           = W;
        if (appIcon != null) Icon = appIcon;

        int tbH = 34;
        var titleBar = new Panel { BackColor = _bg, Location = new Point(0, 0), Size = new Size(W, tbH) };
        var logo = TryImage(logoIcon);
        int afterLogo = 12;
        if (logo != null)
        {
            int lh = 20, lw = Math.Max(20, (int)Math.Round(logo.Width * (lh / (double)logo.Height)));
            lw = Math.Min(lw, 150);
            titleBar.Controls.Add(new PictureBox { Image = logo, SizeMode = PictureBoxSizeMode.Zoom,
                Location = new Point(12, (tbH - lh) / 2), Size = new Size(lw, lh), BackColor = Color.Transparent });
            afterLogo = 12 + lw + 8;
        }
        titleBar.Controls.Add(new Label { Text = Loc.T("Community Edition"), ForeColor = _sub,
            Font = new Font("Segoe UI", 8.5f), AutoSize = true, Location = new Point(afterLogo, 10) });
        Controls.Add(titleBar);

        int hb = 52;
        var header = new Panel { BackColor = head, Location = new Point(0, tbH), Size = new Size(W, hb) };
        var hi = TryImage(hipsIcon);
        int textX = 14;
        if (hi != null)
        {
            header.Controls.Add(new PictureBox { Image = hi, SizeMode = PictureBoxSizeMode.Zoom,
                Location = new Point(14, (hb - 28) / 2), Size = new Size(28, 28), BackColor = Color.Transparent });
            textX = 52;
        }
        header.Controls.Add(new Label
        {
            Text = info.Blocked ? Loc.T("Zablokowano zmianę w systemie") : Loc.T("Wykryto zmianę w systemie"),
            ForeColor = Color.White, Font = new Font("Segoe UI", 11f, FontStyle.Bold),
            AutoSize = false, Location = new Point(textX, 8), Size = new Size(W - textX - 12, 20),
        });
        header.Controls.Add(new Label
        {
            Text = Loc.T("Ochrona składników systemu"), ForeColor = Color.FromArgb(0xF0, 0xE6, 0xE6),
            Font = new Font("Segoe UI", 8.5f),
            AutoSize = false, Location = new Point(textX, 28), Size = new Size(W - textX - 12, 16),
        });
        Controls.Add(header);

        int y = tbH + hb + 12;

        _lblRule = new Label
        {
            ForeColor = _fg, Font = new Font("Segoe UI", 10f, FontStyle.Bold),
            AutoSize = false, Location = new Point(16, y), Size = new Size(W - 32, 20), AutoEllipsis = true,
        };
        Controls.Add(_lblRule);
        y += 24;

        const int detailH = 76;
        _lblDetail = new Label
        {
            ForeColor = _sub, Font = new Font("Segoe UI", 9f),
            AutoSize = false, Location = new Point(16, y), Size = new Size(W - 32, detailH),
        };
        Controls.Add(_lblDetail);
        y += detailH + 10;

        var infoBox = new Panel { BackColor = _box, Location = new Point(16, y), Size = new Size(W - 32, 74) };
        _lblWhereK = new Label { ForeColor = _sub, Font = new Font("Segoe UI", 8f),
            AutoSize = false, Location = new Point(10, 8), Size = new Size(W - 52, 13) };
        _lblWhereV = new Label { ForeColor = _fg, Font = new Font("Segoe UI", 9f, FontStyle.Bold),
            AutoSize = false, Location = new Point(10, 21), Size = new Size(W - 52, 16), AutoEllipsis = true };
        infoBox.Controls.Add(new Label { Text = Loc.T("Proces"), ForeColor = _sub, Font = new Font("Segoe UI", 8f),
            AutoSize = false, Location = new Point(10, 42), Size = new Size(W - 52, 13) });
        _lblProcV = new Label { ForeColor = _fg, Font = new Font("Segoe UI", 9f, FontStyle.Bold),
            AutoSize = false, Location = new Point(10, 55), Size = new Size(W - 52, 16), AutoEllipsis = true };
        infoBox.Controls.Add(_lblWhereK); infoBox.Controls.Add(_lblWhereV); infoBox.Controls.Add(_lblProcV);
        Controls.Add(infoBox);
        y += 74 + 12;

        int bh = 32;
        if (_decide)
        {
            int half = (W - 32 - 8) / 2;
            var btnFix = MakeBtn("✓ Napraw", new Point(16, y), new Size(half, bh),
                                 Color.White, Color.FromArgb(0x2F, 0x7A, 0x3A), true);
            btnFix.Click += (_, __) => Answer(a => a.OnFix);
            var btnAllow = MakeBtn(Loc.T("Zezwól"), new Point(16 + half + 8, y), new Size(half, bh), _fg, _bg, false);
            btnAllow.Click += (_, __) => Answer(a => a.OnAllow);
            Controls.Add(btnFix); Controls.Add(btnAllow);
            y += bh + 8;

            var btnDet = MakeBtn(Loc.T("Szczegóły w dzienniku zdarzeń"), new Point(16, y), new Size(W - 32, 26), _sub, _bg, false);
            btnDet.Click += (_, __) => { try { onDetails?.Invoke(); } catch { } Close(); };
            Controls.Add(btnDet);
            y += 26 + 10;

            BuildPager(y);
            y += 24 + 12;
        }
        else
        {
            int half = (W - 32 - 8) / 2;
            var btnDet = MakeBtn(Loc.T("Szczegóły"), new Point(16, y), new Size(half, bh), _fg, _bg, false);
            btnDet.Click += (_, __) => { try { onDetails?.Invoke(); } catch { } Close(); };
            var btnOk = MakeBtn("OK", new Point(16 + half + 8, y), new Size(half, bh),
                                Color.White, Color.FromArgb(0x1E, 0x7A, 0xCC), true);
            btnOk.Click += (_, __) => Close();
            Controls.Add(btnDet); Controls.Add(btnOk);
            y += bh + 14;

            var t = new System.Windows.Forms.Timer { Interval = 18000 };
            t.Tick += (_, __) => { t.Stop(); t.Dispose(); try { Close(); } catch { } };
            t.Start();
        }

        Height = y;
        var wa = Screen.PrimaryScreen!.WorkingArea;
        Location = new Point(wa.Right - Width - 12, wa.Bottom - Height - 12);
        PopupStackManager.Register(this);

        ShowItem();
        if (_decide) _live = this;
    }

    private void BuildPager(int y)
    {
        const int pw = 28, lw = 90, gap = 10;
        int x = W - 16 - (pw + gap + lw + gap + pw);

        _btnPrev = MakeBtn("‹", new Point(x, y), new Size(pw, 24), _fg, _box, false);
        _btnPrev.Click += (_, __) => { if (_idx > 0) { _idx--; ShowItem(); } };

        _lblPager = new Label
        {
            ForeColor = _sub, AutoSize = false, TextAlign = ContentAlignment.MiddleCenter,
            Location = new Point(x + pw + gap, y), Size = new Size(lw, 24),
            Font = new Font("Segoe UI", 8.5f), BackColor = _bg,
        };

        _btnNext = MakeBtn("›", new Point(x + pw + gap + lw + gap, y), new Size(pw, 24), _fg, _box, false);
        _btnNext.Click += (_, __) => { if (_idx < _items.Count - 1) { _idx++; ShowItem(); } };

        Controls.Add(_btnPrev); Controls.Add(_lblPager); Controls.Add(_btnNext);
    }

    public bool Enqueue(Info info, Action? onFix, Action? onAllow)
    {
        if (IsDisposed || Disposing || !_decide) return false;
        try
        {
            if (InvokeRequired) return (bool)Invoke(new Func<bool>(() => Enqueue(info, onFix, onAllow)));

            if (_items.Exists(i => i.Info == info)) return true;
            _items.Add(new Item(info, onFix, onAllow));
            ShowItem();
            return true;
        }
        catch { return false; }
    }

    private void Answer(Func<Item, Action?> pick)
    {
        if (_items.Count == 0) { Close(); return; }
        var item = _items[Math.Clamp(_idx, 0, _items.Count - 1)];
        try { pick(item)?.Invoke(); } catch { }

        _items.Remove(item);
        if (_items.Count == 0) { Close(); return; }
        if (_idx >= _items.Count) _idx = _items.Count - 1;
        ShowItem();
    }

    private void ShowItem()
    {
        if (_items.Count == 0) return;
        _idx = Math.Clamp(_idx, 0, _items.Count - 1);
        var info = _items[_idx].Info;

        _lblRule.Text   = Loc.T(info.RuleName);
        _lblDetail.Text = Loc.T(info.Detail);
        _lblWhereK.Text = info.Kind.Length > 0 ? Loc.F("Obiekt ({0})", info.Kind) : Loc.T("Obiekt");
        _lblWhereV.Text = info.Where.Length > 0 ? info.Where : "—";
        _lblProcV.Text  = info.Process.Length > 0 ? info.Process : "—";

        bool wiele = _items.Count > 1;
        if (_lblPager != null) _lblPager.Text = wiele ? Loc.F("{0} z {1}", _idx + 1, _items.Count) : "";
        if (_btnPrev != null) { _btnPrev.Visible = wiele; _btnPrev.Enabled = _idx > 0; }
        if (_btnNext != null) { _btnNext.Visible = wiele; _btnNext.Enabled = _idx < _items.Count - 1; }
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        if (ReferenceEquals(_live, this)) _live = null;
        PopupStackManager.Unregister(this);
        base.OnFormClosed(e);
    }

    private Button MakeBtn(string text, Point loc, Size size, Color fore, Color back, bool solid)
    {
        var b = new Button { Text = text, Location = loc, Size = size, FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI", 9f, solid ? FontStyle.Bold : FontStyle.Regular),
            ForeColor = fore, BackColor = back, Cursor = Cursors.Hand };
        b.FlatAppearance.BorderColor = solid ? back : _border;
        return b;
    }

    private static Image? TryImage(byte[]? bytes)
    {
        if (bytes == null) return null;
        try { using var ms = new MemoryStream(bytes); return Image.FromStream(ms); }
        catch { return null; }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        using var p = new Pen(_border);
        e.Graphics.DrawRectangle(p, 0, 0, Width - 1, Height - 1);
    }
}
