using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;
using Malward.AppGUI.Services;

namespace Malward.AppGUI;

public sealed class RichInfoPopupForm : Form, IShieldPopupHost
{
    private const int W  = 540;
    private const int M  = 20;
    private const int CW = W - 2 * M;

    protected override bool ShowWithoutActivation => true;

    public enum BodyMode
    {
        KeyValue,

        Text,
    }

    public sealed record Entry(
        string Title,
        string Detection,
        string? Path,
        string? File,
        string? Process,
        IReadOnlyList<string>? Items = null,
        string? Body = null,

        string? FullPath = null,
        IReadOnlyList<string>? QuarantineIds = null)
    {
        public int Repeats { get; set; }

        public string Key => Title + "" + Detection + "" + Path + "" + File;
    }

    public sealed class Group
    {
        public required string Kind { get; init; }
        public required string BannerText { get; init; }
        public required Color HeaderColor { get; init; }
        public byte[]? IconPng { get; init; }
        public byte[]? LogoPng { get; init; }
        public required string ButtonText { get; init; }
        public Action? OnButton { get; init; }
        public BodyMode Mode { get; init; } = BodyMode.KeyValue;
        public List<Entry> Entries { get; } = new();

        public Action<Entry>? OnRestore { get; init; }
        public Action<Entry>? OnRestoreAndExclude { get; init; }
        public string RestoreText { get; init; } = Loc.T("Przywróć");
        public string RestoreExcludeText { get; init; } = Loc.T("Przywróć i nie blokuj ponownie");
    }

    private readonly Color _bg, _fg, _sub, _surface, _border;
    private readonly Group _group;
    private int _idx;
    private Button? _btnRestore, _btnRestoreEx;

    private readonly BannerStrip _banners;
    private readonly Panel _headPanel;
    private readonly Label _headTitle;
    private PictureBox? _headIcon;

    private readonly Panel _kvPanel, _textPanel;
    private Label _vDet = null!, _vPath = null!, _vFile = null!, _vProc = null!;
    private readonly Label _lblBody;
    private readonly ListBox _list;

    private readonly Button _mainButton;
    private Label? _lblPager;
    private Button? _btnPrev, _btnNext;

    private System.Windows.Forms.Timer? _auto;
    private int _autoDismissSec;
    private int _baseHeight;

    private readonly List<Form> _children = new();

    public Rectangle HostBounds => Bounds;

    public void AddOrUpdateBanner(string key, string text, Action onShow)
    {
        if (IsDisposed || Disposing) return;
        if (InvokeRequired) { BeginInvoke(new Action(() => AddOrUpdateBanner(key, text, onShow))); return; }
        _banners.AddOrUpdate(key, text, onShow);
    }

    public void RegisterChild(Form child)
    {
        _children.Add(child);
        child.FormClosed += (_, __) => _children.Remove(child);
    }

    private static RichInfoPopupForm? _live;
    public static RichInfoPopupForm? Live =>
        _live is { IsDisposed: false, Disposing: false } f ? f : null;

    public RichInfoPopupForm(bool dark, Color headerColor, byte[]? iconPng,
        string title, string body, IEnumerable<string>? listItems,
        string buttonText, Action? onButton = null, int autoDismissSec = 0, byte[]? logoPng = null)
        : this(dark, new Group
               {
                   Kind = "repair", BannerText = title, HeaderColor = headerColor,
                   IconPng = iconPng, LogoPng = logoPng, ButtonText = buttonText, OnButton = onButton,
                   Mode = BodyMode.Text,
               }.With(new Entry(title, "", null, null, null,
                                listItems?.Where(s => !string.IsNullOrEmpty(s)).ToList(), body)),
               autoDismissSec)
    {
    }

    public RichInfoPopupForm(bool dark, Group group, int autoDismissSec = 0)
    {
        _group = group;
        _autoDismissSec = autoDismissSec;

        _bg      = dark ? Color.FromArgb(0x16, 0x1B, 0x22) : Color.White;
        _fg      = dark ? Color.FromArgb(0xE9, 0xEC, 0xF0) : Color.FromArgb(0x0E, 0x11, 0x16);
        _sub     = dark ? Color.FromArgb(0x9C, 0xA3, 0xAF) : Color.FromArgb(0x55, 0x5C, 0x66);
        _border  = dark ? Color.FromArgb(0x2B, 0x33, 0x3E) : Color.FromArgb(0xC9, 0xCF, 0xD6);
        _surface = dark ? Color.FromArgb(0x1C, 0x23, 0x2C) : Color.FromArgb(0xF6, 0xF8, 0xFA);

        FormBorderStyle = FormBorderStyle.None;
        ShowInTaskbar   = false;
        TopMost         = true;
        StartPosition   = FormStartPosition.Manual;
        BackColor       = _bg;
        Width           = W;
        DoubleBuffered  = true;
        Font            = new Font("Segoe UI", 9f);

        var titleBar = new Panel { Dock = DockStyle.Top, Height = 32, BackColor = _surface };
        var logo = TryImage(group.LogoPng);
        int brandX = 12;
        if (logo != null)
        {
            int lh = 18, lw = Math.Max(18, (int)Math.Round(logo.Width * (lh / (double)logo.Height)));
            lw = Math.Min(lw, 130);
            titleBar.Controls.Add(new PictureBox { Image = logo, SizeMode = PictureBoxSizeMode.Zoom,
                Location = new Point(12, 7), Size = new Size(lw, lh), BackColor = _surface });
            brandX = 12 + lw + 8;
        }
        titleBar.Controls.Add(new Label
        {
            Text = Loc.T("Community Edition"), ForeColor = _sub, AutoSize = false,
            Location = new Point(brandX, 0), Size = new Size(W - brandX - 44, 32),
            TextAlign = ContentAlignment.MiddleLeft, Font = new Font("Segoe UI", 8.5f),
        });
        var btnX = new Button
        {
            Text = "✕", Dock = DockStyle.Right, Width = 40, FlatStyle = FlatStyle.Flat,
            ForeColor = _fg, BackColor = _surface, TabStop = false,
        };
        btnX.FlatAppearance.BorderSize = 0;
        btnX.Click += (_, __) => { try { Close(); } catch { } };
        titleBar.Controls.Add(btnX);

        _banners = new BannerStrip(RecalcHeight);

        _headPanel = new Panel { Dock = DockStyle.Top, Height = 74, BackColor = group.HeaderColor };
        _headTitle = new Label
        {
            ForeColor = Color.White, Font = new Font("Segoe UI", 15f, FontStyle.Bold),
            AutoSize = false, Location = new Point(74, 0), Size = new Size(W - 86, 74),
            TextAlign = ContentAlignment.MiddleLeft, BackColor = Color.Transparent,
        };
        _headPanel.Controls.Add(_headTitle);

        var body = new Panel { Dock = DockStyle.Fill, BackColor = _bg };
        bool kv = group.Mode == BodyMode.KeyValue;

        _kvPanel = new Panel { BackColor = _bg, Location = new Point(0, 8), Size = new Size(W, 108), Visible = kv };
        int ky = 6;
        AddRow(_kvPanel, Loc.T("Detekcja"), out _vDet, ref ky, bold: true, accent: true);
        AddRow(_kvPanel, Loc.T("Ścieżka"),  out _vPath, ref ky);
        AddRow(_kvPanel, Loc.T("Plik"),     out _vFile, ref ky, bold: true);
        AddRow(_kvPanel, Loc.T("Proces"),   out _vProc, ref ky);
        body.Controls.Add(_kvPanel);

        _textPanel = new Panel { BackColor = _bg, Location = new Point(0, 8), Size = new Size(W, 108), Visible = !kv };
        _lblBody = new Label
        {
            ForeColor = _sub, Font = new Font("Segoe UI", 9f), AutoSize = false,
            Location = new Point(M, 4), Size = new Size(CW, 34),
        };
        _list = new ListBox
        {
            Location = new Point(M, 42), Size = new Size(CW, 62),
            BackColor = _surface, ForeColor = _fg, BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Segoe UI", 8.5f), IntegralHeight = false, SelectionMode = SelectionMode.None,
            HorizontalScrollbar = true,
        };
        _textPanel.Controls.Add(_lblBody);
        _textPanel.Controls.Add(_list);
        body.Controls.Add(_textPanel);

        int y = 8 + 108 + 8;

        _mainButton = new Button
        {
            Text = group.ButtonText, Location = new Point(M, y), Size = new Size(CW, 36),
            FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            ForeColor = _fg, BackColor = _surface, Cursor = Cursors.Hand,
        };
        _mainButton.FlatAppearance.BorderColor = _border;
        _mainButton.Click += (_, __) =>
        {
            try { _group.OnButton?.Invoke(); } catch { }
            try { Close(); } catch { }
        };
        body.Controls.Add(_mainButton);
        y += 36 + 10;

        if (group.OnRestore != null)
        {
            _autoDismissSec = 0;
            int bw = (CW - 8) / 2;
            _btnRestore = MakeDecisionButton(group.RestoreText);
            _btnRestore.Location = new Point(M, y); _btnRestore.Size = new Size(bw, 32);
            _btnRestore.Click += (_, __) => Decide(exclude: false);
            _btnRestoreEx = MakeDecisionButton(group.RestoreExcludeText);
            _btnRestoreEx.Location = new Point(M + bw + 8, y); _btnRestoreEx.Size = new Size(bw, 32);
            _btnRestoreEx.Click += (_, __) => Decide(exclude: true);
            body.Controls.Add(_btnRestore); body.Controls.Add(_btnRestoreEx);
            y += 32 + 10;
        }

        BuildPager(body, y);
        y += 24 + 14;

        Controls.Add(body);
        Controls.Add(_headPanel);
        Controls.Add(_banners);
        Controls.Add(titleBar);

        _baseHeight = 32 + _headPanel.Height + y;
        Height = _baseHeight;
        Reposition();
        PopupStackManager.Register(this);

        Refresh_();
        RestartAutoDismiss();
        _live = this;

        if (ShieldPopupHub.Host == null) ShieldPopupHub.SetHost(this);
    }

    private void AddRow(Panel parent, string key, out Label val, ref int y,
                        bool bold = false, bool accent = false)
    {
        parent.Controls.Add(new Label
        {
            Text = key, ForeColor = _sub, AutoSize = false,
            Location = new Point(M, y), Size = new Size(70, 20), Font = new Font("Segoe UI", 8.5f),
        });
        val = new Label
        {
            ForeColor = accent ? Color.FromArgb(0xC0, 0x2A, 0x2A) : _fg, AutoSize = false,
            Location = new Point(M + 70, y), Size = new Size(CW - 70, 20),
            Font = new Font("Segoe UI", 8.5f, bold ? FontStyle.Bold : FontStyle.Regular),
            AutoEllipsis = true,
        };
        parent.Controls.Add(val);
        y += 26;
    }

    private void BuildPager(Panel parent, int y)
    {
        const int pw = 28, lw = 90, gap = 10;
        int x = M + CW - (pw + gap + lw + gap + pw);

        _btnPrev = MakePagerButton("‹");
        _btnPrev.Location = new Point(x, y);
        _btnPrev.Click += (_, __) => { if (_idx > 0) { _idx--; Refresh_(); RestartAutoDismiss(); } };

        _lblPager = new Label
        {
            ForeColor = _sub, AutoSize = false, TextAlign = ContentAlignment.MiddleCenter,
            Location = new Point(x + pw + gap, y), Size = new Size(lw, 24),
            Font = new Font("Segoe UI", 8.5f), BackColor = _bg,
        };

        _btnNext = MakePagerButton("›");
        _btnNext.Location = new Point(x + pw + gap + lw + gap, y);
        _btnNext.Click += (_, __) =>
        {
            if (_idx < _group.Entries.Count - 1) { _idx++; Refresh_(); RestartAutoDismiss(); }
        };

        parent.Controls.Add(_btnPrev);
        parent.Controls.Add(_lblPager);
        parent.Controls.Add(_btnNext);
    }

    private Button MakePagerButton(string text)
    {
        var b = new Button
        {
            Text = text, Size = new Size(28, 24), FlatStyle = FlatStyle.Flat,
            BackColor = _surface, ForeColor = _fg, TabStop = false,
            Font = new Font("Segoe UI", 11f, FontStyle.Bold), Cursor = Cursors.Hand,
        };
        b.FlatAppearance.BorderColor = _border;
        b.FlatAppearance.BorderSize = 1;
        return b;
    }

    public bool AppendLive(string kind, Entry entry)
    {
        if (IsDisposed || Disposing || _group.Kind != kind) return false;
        try
        {
            if (InvokeRequired) return (bool)Invoke(new Func<bool>(() => AppendLive(kind, entry)));
            var istniejacy = _group.Entries.FirstOrDefault(x => x.Key == entry.Key);
            if (istniejacy != null) istniejacy.Repeats++;
            else _group.Entries.Add(entry);
            Refresh_();
            RestartAutoDismiss();
            return true;
        }
        catch { return false; }
    }

    private Button MakeDecisionButton(string text)
    {
        var b = new Button
        {
            Text = text, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f, FontStyle.Bold),
            ForeColor = _fg, BackColor = _surface, Cursor = Cursors.Hand,
        };
        b.FlatAppearance.BorderColor = _border;
        return b;
    }

    private void Decide(bool exclude)
    {
        if (_group.Entries.Count == 0) return;
        var e = _group.Entries[Math.Clamp(_idx, 0, _group.Entries.Count - 1)];
        try { (exclude ? _group.OnRestoreAndExclude : _group.OnRestore)?.Invoke(e); } catch { }
        _group.Entries.Remove(e);
        if (_group.Entries.Count == 0) { try { Close(); } catch { } return; }
        Refresh_();
    }

    private void Refresh_()
    {
        if (_group.Entries.Count == 0) return;
        _idx = Math.Clamp(_idx, 0, _group.Entries.Count - 1);
        var e = _group.Entries[_idx];

        if (_btnRestore != null && _btnRestoreEx != null)
        {
            bool can = e.QuarantineIds is { Count: > 0 };
            _btnRestore.Enabled = can;
            _btnRestoreEx.Enabled = can || !string.IsNullOrEmpty(e.FullPath);
        }

        _headTitle.Text = e.Repeats > 0 ? Loc.F("{0}  (×{1})", Loc.T(e.Title), e.Repeats + 1) : Loc.T(e.Title);
        SetHeaderIcon(_group.IconPng);

        if (_group.Mode == BodyMode.KeyValue)
        {
            _vDet.Text  = string.IsNullOrWhiteSpace(e.Detection) ? "—" : e.Detection;

            _vPath.Text = !string.IsNullOrWhiteSpace(e.Path) ? e.Path!
                        : !string.IsNullOrWhiteSpace(e.File) ? e.File! : "—";
            _vFile.Text = string.IsNullOrWhiteSpace(e.File) ? "—" : e.File!;
            _vProc.Text = string.IsNullOrWhiteSpace(e.Process) ? "—" : e.Process!;
        }
        else
        {
            _lblBody.Text = e.Body ?? "";
            _list.BeginUpdate();
            _list.Items.Clear();
            if (e.Items != null) foreach (var it in e.Items) _list.Items.Add(it);
            _list.EndUpdate();
            _list.Visible = _list.Items.Count > 0;
            _lblBody.Size = new Size(CW, _list.Visible ? 34 : 100);
        }

        bool wiele = _group.Entries.Count > 1;
        if (_lblPager != null) _lblPager.Text = wiele ? Loc.F("{0} z {1}", _idx + 1, _group.Entries.Count) : "";
        if (_btnPrev != null) { _btnPrev.Visible = wiele; _btnPrev.Enabled = _idx > 0; }
        if (_btnNext != null) { _btnNext.Visible = wiele; _btnNext.Enabled = _idx < _group.Entries.Count - 1; }
    }

    private void SetHeaderIcon(byte[]? png)
    {
        var img = TryImage(png);
        if (img == null) return;
        if (_headIcon == null)
        {
            _headIcon = new PictureBox
            {
                SizeMode = PictureBoxSizeMode.Zoom, Location = new Point(20, (74 - 38) / 2),
                Size = new Size(38, 38), BackColor = Color.Transparent,
            };
            _headPanel.Controls.Add(_headIcon);
        }
        _headIcon.Image = img;
    }

    private void RecalcHeight()
    {
        if (_baseHeight <= 0) return;
        int nowa = _baseHeight + _banners.Height;
        if (nowa == Height) return;
        Height = nowa;
        Reposition();
    }

    private void Reposition()
    {
        try
        {
            var wa = Screen.PrimaryScreen!.WorkingArea;
            Location = new Point(wa.Right - Width - 12, wa.Bottom - Height - 12);
        }
        catch { }
    }

    private void RestartAutoDismiss()
    {
        if (_autoDismissSec <= 0) return;
        try { _auto?.Stop(); _auto?.Dispose(); } catch { }
        _auto = new System.Windows.Forms.Timer { Interval = _autoDismissSec * 1000 };
        _auto.Tick += (_, __) => { _auto!.Stop(); try { Close(); } catch { } };
        _auto.Start();
    }

    private static Image? TryImage(byte[]? bytes)
    {
        if (bytes == null) return null;
        try { using var ms = new MemoryStream(bytes); return Image.FromStream(ms); }
        catch { return null; }
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        try { _auto?.Dispose(); } catch { }
        foreach (var c in _children.ToArray())
        {
            try { if (!c.IsDisposed) c.Close(); } catch { }
        }
        _children.Clear();
        if (ReferenceEquals(_live, this)) _live = null;
        ShieldPopupHub.ClearHost(this);
        PopupStackManager.Unregister(this);
        base.OnFormClosed(e);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        using var p = new Pen(_border);
        e.Graphics.DrawRectangle(p, 0, 0, Width - 1, Height - 1);
    }
}

internal static class GroupExtensions
{
    public static RichInfoPopupForm.Group With(this RichInfoPopupForm.Group g, RichInfoPopupForm.Entry e)
    {
        g.Entries.Add(e);
        return g;
    }
}
