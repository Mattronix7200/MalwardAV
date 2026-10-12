using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Media;
using System.Windows.Forms;
using Malward.AppGUI.Services;

namespace Malward.AppGUI;

public sealed class NetworkAlertForm : Form
{
    public sealed record Item(string Path, string? Detection);

    private readonly AssetPack? _assets;
    private readonly bool _sound;
    private readonly List<Item> _items = new();
    private int _idx;

    public Action? OnOpenActivity;

    private const int M  = 20;
    private const int CW = 500;

    private readonly Color _bg, _fg, _sub, _surface, _border;
    private static readonly Color Green = Color.FromArgb(0x2F, 0xAF, 0x5A);
    private static readonly Color Det   = Color.FromArgb(0xE2, 0x3B, 0x3B);

    private Label _lblHeadSub = null!, _lblPathVal = null!, _lblDetVal = null!, _lblPager = null!;
    private Button _btnPrev = null!, _btnNext = null!;
    private System.Windows.Forms.Timer? _autoDismiss;

    public NetworkAlertForm(bool dark, IEnumerable<Item> items, AssetPack? assets = null, bool sound = true)
    {
        _assets = assets; _sound = sound;
        _items.AddRange(items);

        if (dark)
        {
            _bg = Color.FromArgb(0x16, 0x1B, 0x22); _fg = Color.FromArgb(0xE9, 0xEC, 0xF0);
            _sub = Color.FromArgb(0x9C, 0xA3, 0xAF); _surface = Color.FromArgb(0x1C, 0x23, 0x2C);
            _border = Color.FromArgb(0x2B, 0x33, 0x3E);
        }
        else
        {
            _bg = Color.White; _fg = Color.FromArgb(0x0E, 0x11, 0x16);
            _sub = Color.FromArgb(0x6A, 0x72, 0x80); _surface = Color.FromArgb(0xF4, 0xF5, 0xF7);
            _border = Color.FromArgb(0xC9, 0xCF, 0xD6);
        }

        BuildUi();
        PlaySound();
    }

    protected override bool ShowWithoutActivation => true;

    private void BuildUi()
    {
        FormBorderStyle = FormBorderStyle.None;
        ShowInTaskbar = false;
        TopMost = true;
        StartPosition = FormStartPosition.Manual;
        Width = 540;
        BackColor = _bg;
        Font = new Font("Segoe UI", 9f);
        DoubleBuffered = true;

        var titleBar = new Panel { Dock = DockStyle.Top, Height = 32, BackColor = _surface };
        titleBar.Controls.Add(new Label
        {
            Text = "  Malward  ·  Community Edition",
            ForeColor = _sub, AutoSize = false, Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft, Font = new Font("Segoe UI", 8.5f),
        });
        var btnX = new Button
        {
            Text = "✕", Dock = DockStyle.Right, Width = 40, FlatStyle = FlatStyle.Flat,
            ForeColor = _fg, BackColor = _surface, TabStop = false,
        };
        btnX.FlatAppearance.BorderSize = 0;
        btnX.Click += (_, _) => Dismiss();
        titleBar.Controls.Add(btnX);

        var headPanel = new Panel { Dock = DockStyle.Top, Height = 92, BackColor = Green };
        headPanel.Paint += (_, e) => PaintHeaderCheck(e.Graphics);
        headPanel.Controls.Add(new Label
        {
            Text = Loc.T("Zablokowano pobrany plik!"),
            ForeColor = Color.White, Font = new Font("Segoe UI", 16f, FontStyle.Bold),
            AutoSize = false, Location = new Point(86, 18), Size = new Size(430, 30),
        });
        _lblHeadSub = new Label
        {
            ForeColor = Color.FromArgb(235, 255, 255, 255),
            Font = new Font("Segoe UI", 8.5f),
            AutoSize = false, Location = new Point(86, 50), Size = new Size(440, 36),
        };
        headPanel.Controls.Add(_lblHeadSub);

        var body = new Panel { Dock = DockStyle.Fill, BackColor = _bg };

        int y = 14;
        body.Controls.Add(new Label { Text = Loc.T("Plik:"), ForeColor = _sub, AutoSize = false,
            Location = new Point(M, y), Size = new Size(64, 20), Font = new Font("Segoe UI", 8.5f) });
        _lblPathVal = new Label { ForeColor = _fg, AutoSize = false,
            Location = new Point(M + 64, y), Size = new Size(CW - 64, 36),
            Font = new Font("Segoe UI", 8.5f, FontStyle.Bold) };
        body.Controls.Add(_lblPathVal);
        y += 38;

        body.Controls.Add(new Label { Text = Loc.T("Detekcja:"), ForeColor = _sub, AutoSize = false,
            Location = new Point(M, y), Size = new Size(64, 20), Font = new Font("Segoe UI", 8.5f) });
        _lblDetVal = new Label { ForeColor = Det, AutoSize = false,
            Location = new Point(M + 64, y), Size = new Size(CW - 64, 36),
            Font = new Font("Segoe UI", 8.5f, FontStyle.Bold) };
        body.Controls.Add(_lblDetVal);
        y += 38;

        y += 6;
        body.Controls.Add(new Label
        {
            Text = Loc.T("Osłona sieciowa rozpoznała szkodliwy plik podczas pobierania. Jesteś bezpieczny."),
            ForeColor = _sub, AutoSize = false, Location = new Point(M, y),
            Size = new Size(CW, 32), Font = new Font("Segoe UI", 8.5f),
        });
        y += 36;

        var btnAct = new Button
        {
            Text = Loc.T("Pokaż aktywność osłony sieciowej"),
            FlatStyle = FlatStyle.Flat, BackColor = Green, ForeColor = Color.White,
            Font = new Font("Segoe UI", 9f), TabStop = false, Cursor = Cursors.Hand,
            Location = new Point(M, y), Size = new Size(CW, 38),
        };
        btnAct.FlatAppearance.BorderSize = 0;
        btnAct.Click += (_, _) => { OnOpenActivity?.Invoke(); Dismiss(); };
        body.Controls.Add(btnAct);
        y += 46;

        BuildPager(body, ref y);

        Height = 32 + 92 + (y + 16);

        Controls.Add(body);
        Controls.Add(headPanel);
        Controls.Add(titleBar);

        Paint += (_, e) => ControlPaint.DrawBorder(e.Graphics, ClientRectangle, _border, ButtonBorderStyle.Solid);

        RefreshItem();
        PositionBottomRight();

        _autoDismiss = new System.Windows.Forms.Timer { Interval = 12000 };
        _autoDismiss.Tick += (_, _) => { _autoDismiss!.Stop(); Dismiss(); };
        _autoDismiss.Start();
    }

    private void BuildPager(Panel parent, ref int y)
    {
        const int pw = 28, lw = 90, gap = 4;
        int total = pw + gap + lw + gap + pw;
        int x = M + CW - total;

        _btnPrev = MakePager("←");
        _btnPrev.Location = new Point(x, y);
        _btnPrev.Click += (_, _) => { if (_idx > 0) { _idx--; RefreshItem(); BumpDismiss(); } };

        _lblPager = new Label
        {
            ForeColor = _sub, AutoSize = false, TextAlign = ContentAlignment.MiddleCenter,
            Location = new Point(x + pw + gap, y), Size = new Size(lw, 24),
            Font = new Font("Segoe UI", 8.5f), BackColor = _bg,
        };

        _btnNext = MakePager("→");
        _btnNext.Location = new Point(x + pw + gap + lw + gap, y);
        _btnNext.Click += (_, _) => { if (_idx < _items.Count - 1) { _idx++; RefreshItem(); BumpDismiss(); } };

        parent.Controls.Add(_btnPrev);
        parent.Controls.Add(_lblPager);
        parent.Controls.Add(_btnNext);
        y += 30;
    }

    private Button MakePager(string text)
    {
        var b = new Button
        {
            Text = text, Size = new Size(30, 24), FlatStyle = FlatStyle.Flat,
            BackColor = _bg, ForeColor = _fg, TabStop = false, Font = new Font("Segoe UI", 10f),
        };
        b.FlatAppearance.BorderSize = 0;
        return b;
    }

    private void PaintHeaderCheck(Graphics g)
    {
        g.SmoothingMode = SmoothingMode.AntiAlias;
        var rect = new Rectangle(20, 22, 48, 48);
        using var pen = new Pen(Color.FromArgb(230, 255, 255, 255), 4);
        g.DrawEllipse(pen, rect);
        g.DrawLines(pen, new[] { new Point(33, 46), new Point(42, 55), new Point(57, 38) });
    }

    private void PositionBottomRight()
    {
        var wa = Screen.PrimaryScreen!.WorkingArea;
        Location = new Point(wa.Right - Width - 16, wa.Bottom - Height - 16);
        PopupStackManager.Register(this);
    }

    public void Append(IEnumerable<Item> items)
    {
        var keys = new HashSet<string>(_items.Select(i => i.Path));
        foreach (var it in items) if (keys.Add(it.Path)) _items.Add(it);
        RefreshItem();
        PlaySound();
        if (_autoDismiss != null) { _autoDismiss.Stop(); _autoDismiss.Start(); }
    }

    private void RefreshItem()
    {
        if (_items.Count == 0) return;
        if (_idx >= _items.Count) _idx = _items.Count - 1;
        if (_idx < 0) _idx = 0;

        var it = _items[_idx];
        _lblPathVal.Text = it.Path;
        _lblDetVal.Text  = it.Detection ?? "Malware";

        _lblHeadSub.Text = _items.Count > 1
            ? Loc.F("Zablokowano {0} pobrań szkodliwych plików.", _items.Count)
            : Loc.T("Pobrany plik został rozpoznany jako szkodliwy.");

        _lblPager.Text = Loc.F("{0} z {1}", _idx + 1, _items.Count);
        _btnPrev.Enabled = _idx > 0;
        _btnNext.Enabled = _idx < _items.Count - 1;
    }

    private void BumpDismiss()
    {
        if (_autoDismiss == null) return;
        _autoDismiss.Stop(); _autoDismiss.Start();
    }

    private void Dismiss()
    {
        try { _autoDismiss?.Stop(); } catch { }
        Close();
    }

    private void PlaySound()
    {
        if (!_sound) return;
        try
        {
            if (_assets != null && _assets.TryGet("notify01.wav", out var wav))
            {
                var player = new SoundPlayer(new MemoryStream(wav));
                player.Play();
            }
        }
        catch { }
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        try { _autoDismiss?.Dispose(); } catch { }
        PopupStackManager.Unregister(this);
        base.OnFormClosed(e);
    }
}
