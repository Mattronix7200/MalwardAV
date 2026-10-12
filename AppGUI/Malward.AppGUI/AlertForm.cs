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

public sealed class AlertForm : Form, IShieldPopupHost
{
    private BannerStrip? _banners;

    private readonly List<Form> _children = new();

    private int _baseHeight;

    public Rectangle HostBounds => Bounds;

    public void AddOrUpdateBanner(string key, string text, Action onShow)
    {
        if (IsDisposed || Disposing) return;
        if (InvokeRequired) { BeginInvoke(new Action(() => AddOrUpdateBanner(key, text, onShow))); return; }
        _banners?.AddOrUpdate(key, text, onShow);
    }

    public void RegisterChild(Form child)
    {
        _children.Add(child);
        child.FormClosed += (_, __) => _children.Remove(child);
    }

    private void CloseChildren()
    {
        foreach (var c in _children.ToArray())
        {
            try { if (!c.IsDisposed) c.Close(); } catch { }
        }
        _children.Clear();
    }

    public sealed record Item(string Id, string Name, string File, string Detection,
        string Process = "", string Action = "", string Source = "");

    private readonly string _mode;
    private readonly ResidentIpc _ipc;
    private readonly AssetPack? _assets;
    private readonly bool _dark;
    private readonly bool _sound;

    private const int M  = 20;
    private const int CW = 500;

    private readonly List<Item> _items = new();
    private int _idx;
    private bool _applyAll = true;

    public Action? OnQuickScan;
    public Action? OnOpenQuarantine;

    private readonly Color _bg, _fg, _sub, _surface, _border;
    private static readonly Color Red   = Color.FromArgb(0xE2, 0x3B, 0x3B);
    private static readonly Color Green = Color.FromArgb(0x2F, 0xAF, 0x5A);
    private static readonly Color Det   = Color.FromArgb(0xE2, 0x3B, 0x3B);
    private static readonly Color Info  = Color.FromArgb(0x1E, 0x7A, 0xCC);

    private System.Windows.Forms.Timer? _autoDismiss;

    private Label _lblPathVal = null!, _lblDetVal = null!, _lblPager = null!, _lblHeadSub = null!;
    private Label _lblProcVal = null!, _lblSrc = null!, _lblFileVal = null!;
    private LinkLabel? _quarLink;
    private Panel _headPanel = null!;
    private CheckBox? _chkAll;
    private Button? _btnPrev, _btnNext;

    public string Mode => _mode;

    public AlertForm(string mode, IEnumerable<Item> items, bool dark,
        ResidentIpc ipc, AssetPack? assets, bool sound = true)
    {
        _mode = mode;
        _ipc = ipc;
        _assets = assets;
        _dark = dark;
        _sound = sound;
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

    private void PositionBottomRight()
    {
        var wa = Screen.PrimaryScreen!.WorkingArea;
        Location = new Point(wa.Right - Width - 16, wa.Bottom - Height - 16);
        PopupStackManager.Register(this);

        ShieldPopupHub.SetHost(this);
    }

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

        bool ask = _mode == "ask";
        Color headColor = ask ? Red : Green;

        var titleBar = new Panel { Dock = DockStyle.Top, Height = 32, BackColor = _surface };
        var logoImg = LoadAsset("assets/logo.png") ?? LoadAsset("assets/ic-logo.png");
        int brandX = 12;
        if (logoImg != null)
        {
            int lh = 18, lw = Math.Max(18, (int)Math.Round(logoImg.Width * (lh / (double)logoImg.Height)));
            lw = Math.Min(lw, 130);
            titleBar.Controls.Add(new PictureBox { Image = logoImg, SizeMode = PictureBoxSizeMode.Zoom,
                Location = new Point(12, 7), Size = new Size(lw, lh), BackColor = _surface });
            brandX = 12 + lw + 8;
        }
        var brand = new Label
        {
            Text = Loc.T("Community Edition"),   
            ForeColor = _sub, AutoSize = false,
            Location = new Point(brandX, 0), Size = new Size(Width - brandX - 44, 32),
            TextAlign = ContentAlignment.MiddleLeft, Font = new Font("Segoe UI", 8.5f),
        };
        var btnX = new Button
        {
            Text = "✕", Dock = DockStyle.Right, Width = 40, FlatStyle = FlatStyle.Flat,
            ForeColor = _fg, BackColor = _surface, TabStop = false,
        };
        btnX.FlatAppearance.BorderSize = 0;
        btnX.Click += (_, _) => Dismiss();
        titleBar.Controls.Add(brand);
        titleBar.Controls.Add(btnX);

        _headPanel = new Panel { Dock = DockStyle.Top, Height = 92, BackColor = headColor };
        _headPanel.Paint += (_, e) => PaintHeaderIcon(e.Graphics, ask);
        var headTitle = new Label
        {
            Text = ask ? Loc.T("Zagrożenie wykryte!") : Loc.T("Zablokowano zagrożenie!"),
            ForeColor = Color.White, Font = new Font("Segoe UI", 16f, FontStyle.Bold),
            AutoSize = false, Location = new Point(86, 18), Size = new Size(430, 30),
        };
        _lblHeadSub = new Label
        {
            Text = ask
                ? Loc.T("Znaleźliśmy szkodliwy plik na Twoim komputerze.")
                : Loc.T("Zagrożenie zostało zablokowane przez automatyczną osłonę."),
            ForeColor = Color.FromArgb(235, 255, 255, 255),
            Font = new Font("Segoe UI", 8.5f),
            AutoSize = false, Location = new Point(86, 50), Size = new Size(440, 36),
        };
        _headPanel.Controls.Add(headTitle);
        _headPanel.Controls.Add(_lblHeadSub);

        var body = new Panel { Dock = DockStyle.Fill, BackColor = _bg };

        int y = 12, rowY;

        rowY = y;
        AddKv(body, Loc.T("Detekcja:"), out _lblDetVal, ref y, rightReserve: 168);
        _lblDetVal.ForeColor = Det;
        _lblSrc = new Label
        {
            ForeColor = _sub, AutoSize = false, TextAlign = ContentAlignment.MiddleRight,
            Location = new Point(M + CW - 168, rowY), Size = new Size(168, 20),
            Font = new Font("Segoe UI", 8f),
        };
        body.Controls.Add(_lblSrc);

        AddKv(body, Loc.T("Ścieżka:"), out _lblPathVal, ref y);
        AddKv(body, Loc.T("Plik:"), out _lblFileVal, ref y);

        AddKv(body, Loc.T("Proces:"), out _lblProcVal, ref y);

        y += 6;
        int beltY;

        if (ask)
        {
            var prompt = new Label
            {
                Text = Loc.T("Co chciałbyś zrobić? Pamiętaj — czas reakcji ma znaczenie."),
                ForeColor = _sub, AutoSize = false, Location = new Point(M, y),
                Size = new Size(CW, 18), Font = new Font("Segoe UI", 8.5f),
            };
            body.Controls.Add(prompt);
            y += 24;

            beltY = y;
            int bw = 112;
            var btnQ = MakeButton(Loc.T("Kwarantanna"), true);
            btnQ.Location = new Point(M, beltY); btnQ.Size = new Size(bw, 30);
            btnQ.Click += (_, _) => Decide("quarantine");
            var btnD = MakeButton(Loc.T("Usuń"), false);
            btnD.Location = new Point(M + bw + 8, beltY); btnD.Size = new Size(bw, 30);
            btnD.Click += (_, _) => Decide("delete");
            body.Controls.Add(btnQ); body.Controls.Add(btnD);
            BuildPager(body, beltY + 3);
            y += 36;

            _chkAll = new CheckBox
            {
                Text = Loc.T("Zastosuj tę akcję dla pozostałych detekcji"), Checked = true,
                ForeColor = _sub, AutoSize = false, Location = new Point(M, y), Size = new Size(CW, 22),
                Font = new Font("Segoe UI", 8f, FontStyle.Italic), BackColor = _bg,
            };
            _chkAll.CheckedChanged += (_, _) => _applyAll = _chkAll.Checked;
            body.Controls.Add(_chkAll);
            y += 28;
        }
        else
        {
            beltY = y;

            int bw = (CW - 8) / 2;

            var btnScan = MakeButton(Loc.T("Skanuj komputer"), false);
            btnScan.Location = new Point(M, beltY); btnScan.Size = new Size(bw, 32);

            var scanIcon = LoadScaled("assets/search.png", 15) ?? LoadScaled("assets/ic-scan.png", 15);
            if (scanIcon != null)
            {
                btnScan.Image = scanIcon; btnScan.ImageAlign = ContentAlignment.MiddleLeft;
                btnScan.TextAlign = ContentAlignment.MiddleCenter; btnScan.Padding = new Padding(8, 0, 0, 0);
            }
            btnScan.Click += (_, _) => { OnQuickScan?.Invoke(); Dismiss(); };
            body.Controls.Add(btnScan);

            var btnQuar = MakeButton(Loc.T("Otwórz kwarantannę"), false);
            btnQuar.Location = new Point(M + bw + 8, beltY); btnQuar.Size = new Size(bw, 32);
            var quarIcon = LoadScaled("assets/chest.png", 15);
            if (quarIcon != null)
            {
                btnQuar.Image = quarIcon; btnQuar.ImageAlign = ContentAlignment.MiddleLeft;
                btnQuar.TextAlign = ContentAlignment.MiddleCenter; btnQuar.Padding = new Padding(8, 0, 0, 0);
            }
            btnQuar.Click += (_, _) => { OnOpenQuarantine?.Invoke(); Dismiss(); };
            body.Controls.Add(btnQuar);

            BuildPager(body, beltY + 32 + 12);
            y += 44 + 30;
        }

        _baseHeight = 32 + 92 + (y + 14);
        Height = _baseHeight;

        _banners = new BannerStrip(RecalcHeight);
        Controls.Add(body);
        Controls.Add(_headPanel);
        Controls.Add(_banners);
        Controls.Add(titleBar);

        Paint += (_, e) => ControlPaint.DrawBorder(e.Graphics, ClientRectangle, _border, ButtonBorderStyle.Solid);

        RefreshItem();
        PositionBottomRight();

        if (_mode == "auto")
        {
            _autoDismiss = new System.Windows.Forms.Timer { Interval = 12000 };
            _autoDismiss.Tick += (_, _) => { _autoDismiss!.Stop(); Dismiss(); };
            _autoDismiss.Start();
        }
    }

    private void BuildPager(Panel parent, int y)
    {
        const int pw = 28, lw = 90, gap = 10;
        int total = pw + gap + lw + gap + pw;
        int x = M + CW - total;
        _btnPrev = MakePager("‹");
        _btnPrev.Location = new Point(x, y);
        _btnPrev.Click += (_, _) => { if (_idx > 0) { _idx--; RefreshItem(); BumpDismiss(); } };

        _lblPager = new Label
        {
            ForeColor = _sub, AutoSize = false, TextAlign = ContentAlignment.MiddleCenter,
            Location = new Point(x + pw + gap, y), Size = new Size(lw, 24),
            Font = new Font("Segoe UI", 8.5f), BackColor = _bg,
        };

        _btnNext = MakePager("›");
        _btnNext.Location = new Point(x + pw + gap + lw + gap, y);
        _btnNext.Click += (_, _) => { if (_idx < _items.Count - 1) { _idx++; RefreshItem(); BumpDismiss(); } };

        parent.Controls.Add(_btnPrev);
        parent.Controls.Add(_lblPager);
        parent.Controls.Add(_btnNext);
    }

    private void AddKv(Panel parent, string key, out Label val, ref int y, int rightReserve = 0)
    {
        var k = new Label { Text = key, ForeColor = _sub, AutoSize = false,
            Location = new Point(M, y), Size = new Size(64, 20), Font = new Font("Segoe UI", 8.5f) };

        val = new Label { ForeColor = _fg, AutoSize = false, Location = new Point(M + 64, y),
            Size = new Size(CW - 64 - rightReserve, 20), Font = new Font("Segoe UI", 8.5f, FontStyle.Bold),
            AutoEllipsis = true };
        parent.Controls.Add(k); parent.Controls.Add(val);
        y += 30;
    }

    private static string DetectionSource(string det, string source)
    {
        var fromStage = StageSource(source);
        if (fromStage != null) return fromStage;

        if (string.IsNullOrEmpty(det)) return Loc.T("Baza wirusów");
        var d = det.ToLowerInvariant();
        if (d.Contains("cloud"))                                       return Loc.T("Skaner w chmurze");
        if (d.Contains("heur"))                                        return Loc.T("Heurystyka");

        if (d.Contains("behavior") || d.Contains("behaviour") || d.Contains("ransom"))
            return Loc.T("Analiza behawioralna");
        if (d.Contains("basf") || d.Contains("cert"))                  return Loc.T("Blacklista certyfikatów");
        return Loc.T("Baza wirusów");
    }

    private static string? StageSource(string source)
    {
        var s = (source ?? "").Trim().ToLowerInvariant();
        if (s.Length == 0) return null;
        if (s.Contains("vulnerabledriver"))  return Loc.T("Baza podatnych sterowników");
        if (s.Contains("cloud"))             return Loc.T("Skaner w chmurze");
        if (s.Contains("vps"))               return Loc.T("Baza wirusów");
        if (s.Contains("heur") || s.Contains("yara")) return Loc.T("Heurystyka");
        if (s.Contains("behaviour") || s.Contains("behavior")) return Loc.T("Analiza behawioralna");
        if (s.Contains("masquerade") || s.Contains("shortcut") || s.Contains("name"))
            return Loc.T("Analiza nazwy pliku");
        if (s.Contains("script"))            return Loc.T("Analiza skryptu");
        if (s.Contains("archive"))           return Loc.T("Zawartość archiwum");
        if (s.Contains("cert"))              return Loc.T("Blacklista certyfikatów");
        return null;
    }

    private Image? LoadAsset(string key)
    {
        try { return _assets != null && _assets.TryGet(key, out var b) ? TryImage(b) : null; }
        catch { return null; }
    }

    private Image? LoadScaled(string key, int size)
    {
        try { return _assets != null && _assets.TryGet(key, out var b) ? ScaledImage(b, size) : null; }
        catch { return null; }
    }

    private static Image? TryImage(byte[] bytes)
    {
        try { using var ms = new MemoryStream(bytes); return Image.FromStream(ms); }
        catch { return null; }
    }

    private static Image? ScaledImage(byte[] bytes, int size)
    {
        try
        {
            using var ms = new MemoryStream(bytes);
            using var src = Image.FromStream(ms);
            var bmp = new Bitmap(size, size);
            using var g = Graphics.FromImage(bmp);
            g.InterpolationMode = InterpolationMode.HighQualityBicubic;
            g.DrawImage(src, 0, 0, size, size);
            return bmp;
        }
        catch { return null; }
    }

    private static string FormatProcess(string p)
    {
        try
        {
            var name = Path.GetFileName(p);
            var dir  = Path.GetDirectoryName(p);
            return string.IsNullOrEmpty(dir) ? name : $"{name} ({dir})";
        }
        catch { return p; }
    }

    private Button MakeButton(string text, bool primary)
    {
        var b = new Button
        {
            Text = text, AutoSize = false, Size = new Size(140, 34),
            FlatStyle = FlatStyle.Flat, BackColor = _surface, ForeColor = _fg,
            Font = new Font("Segoe UI", 9f), TabStop = false, Cursor = Cursors.Hand,
        };
        b.FlatAppearance.BorderColor = primary ? Info : _border;
        b.FlatAppearance.BorderSize = primary ? 2 : 1;
        return b;
    }

    private void RecalcHeight()
    {
        if (_baseHeight <= 0) return;
        int nowa = _baseHeight + (_banners?.Height ?? 0);
        if (nowa == Height) return;
        Height = nowa;
        try
        {
            var wa = Screen.PrimaryScreen!.WorkingArea;
            Location = new Point(wa.Right - Width - 12, wa.Bottom - Height - 12);
        }
        catch { }
    }

    private Button MakePager(string text)
    {
        var b = new Button
        {
            Text = text, Size = new Size(28, 24), FlatStyle = FlatStyle.Flat,
            BackColor = _surface, ForeColor = _fg, TabStop = false,
            Font = new Font("Segoe UI", 11f, FontStyle.Bold),
        };
        b.FlatAppearance.BorderColor = _border;
        b.FlatAppearance.BorderSize  = 1;
        return b;
    }

    private void PaintHeaderIcon(Graphics g, bool ask)
    {
        g.SmoothingMode = SmoothingMode.AntiAlias;
        var rect = new Rectangle(20, 22, 48, 48);
        using var pen = new Pen(Color.FromArgb(230, 255, 255, 255), 4);
        g.DrawEllipse(pen, rect);
        if (ask)
        {
            g.DrawLine(pen, 34, 36, 54, 56);
            g.DrawLine(pen, 54, 36, 34, 56);
        }
        else
        {
            g.DrawLines(pen, new[] { new Point(33, 46), new Point(42, 55), new Point(57, 38) });
        }
    }

    public void AppendItems(IEnumerable<Item> items)
    {
        var ids = new HashSet<string>(_items.Select(i => i.Id));
        var pary = new HashSet<string>(_items.Select(Klucz), StringComparer.OrdinalIgnoreCase);
        foreach (var it in items)
            if (ids.Add(it.Id) && pary.Add(Klucz(it))) _items.Add(it);
        RefreshItem();
        PlaySound();
        if (_autoDismiss != null) { _autoDismiss.Stop(); _autoDismiss.Start(); }
    }

    private static string Klucz(Item it) => (it.File ?? "") + "|" + (it.Detection ?? "");

    private void RefreshItem()
    {
        if (_items.Count == 0) return;
        if (_idx >= _items.Count) _idx = _items.Count - 1;
        if (_idx < 0) _idx = 0;

        var it = _items[_idx];

        var full = it.File ?? "";
        string dir = "", name = full;
        try
        {
            var d = System.IO.Path.GetDirectoryName(full);
            if (!string.IsNullOrEmpty(d)) { dir = d; name = System.IO.Path.GetFileName(full); }
        }
        catch { }
        _lblPathVal.Text = string.IsNullOrEmpty(dir) ? full : dir;
        _lblFileVal.Text = string.IsNullOrEmpty(dir) ? "—" : name;
        _lblDetVal.Text  = it.Detection;
        _lblSrc.Text     = Loc.F("[ Detekcja: {0} ]", DetectionSource(it.Detection, it.Source));

        _lblProcVal.Text = string.IsNullOrEmpty(it.Process) ? "—" : FormatProcess(it.Process);

        _lblPager.Text = Loc.F("{0} z {1}", _idx + 1, _items.Count);
        if (_btnPrev != null) _btnPrev.Enabled = _idx > 0;
        if (_btnNext != null) _btnNext.Enabled = _idx < _items.Count - 1;

        if (_mode == "auto") _lblHeadSub.Text = AutoSubtitle();
    }

    private string AutoSubtitle()
    {
        if (_items.Count > 1)
            return Loc.F("Automatyczna osłona zablokowała {0} szkodliwych elementów.", _items.Count);

        return _items[_idx].Action?.ToLowerInvariant() switch
        {
            "delete"     => Loc.T("Szkodliwy plik został usunięty."),
            "quarantine" => Loc.T("Szkodliwy plik został przeniesiony do kwarantanny."),
            "quarantine-reboot" => Loc.T("Kopia trafiła do kwarantanny, ale plik jest zablokowany — "
                                       + "zniknie po ponownym uruchomieniu komputera."),
            "delete-reboot"     => Loc.T("Plik jest zablokowany — zostanie usunięty po ponownym "
                                       + "uruchomieniu komputera."),
            _            => Loc.T("Zagrożenie zostało zablokowane przez automatyczną osłonę."),
        };
    }

    private void Decide(string action)
    {
        if (_items.Count == 0) { Dismiss(); return; }

        if (_applyAll)
        {
            for (int i = _idx; i < _items.Count; i++)
                _ipc.WriteDecision(_items[i].Id, action);
            Dismiss();
        }
        else
        {
            _ipc.WriteDecision(_items[_idx].Id, action);
            _items.RemoveAt(_idx);
            if (_items.Count == 0) { Dismiss(); return; }
            if (_idx >= _items.Count) _idx = _items.Count - 1;
            RefreshItem();
        }
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
        CloseChildren();
        ShieldPopupHub.ClearHost(this);
        try { _autoDismiss?.Dispose(); } catch { }
        PopupStackManager.Unregister(this);
        base.OnFormClosed(e);
    }
}
