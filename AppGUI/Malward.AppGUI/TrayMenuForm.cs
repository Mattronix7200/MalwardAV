using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Windows.Forms;
using Malward.AppGUI.Services;

namespace Malward.AppGUI;

public sealed class TrayMenuForm : Form
{
    public Action? OnOpen;
    public Action? OnQuickScan;
    public Action? OnFullScan;
    public Action? OnCustomScan;
    public Action? OnUpdate;
    public Action? OnQuarantine;
    public Action? OnExit;
    public Action<bool>? OnToggleResident;
    public Action<bool>? OnToggleNetwork;
    public Action<bool>? OnToggleBackup;
    public Action<bool>? OnToggleSnapshots;
    public Action<bool>? OnToggleRemovable;

    private readonly Image? _logoImage;
    private readonly IReadOnlyDictionary<string, Image>? _icons;

    private bool _residentEnabled, _residentAvailable, _residentRunning;
    private bool _networkEnabled,  _networkAvailable,  _networkRunning;
    private bool _backupAvailable,  _backupOn;
    private bool _snapshotsAvailable, _snapshotsOn;
    private bool _removableAvailable,  _removableOn;
    private string _lastUpdate = "—";
    private string _version    = "—";
    private string _dbVersion  = "—";

    private readonly Color _bg, _fg, _sub, _surface, _border;
    private static readonly Color CheckBlue = Color.FromArgb(0x3A, 0xA0, 0xFF);

    private Label _footerLbl = null!;
    private CheckRow _residentSwitch = null!, _networkSwitch = null!;
    private CheckRow _backupSwitch = null!, _snapshotsSwitch = null!, _removableSwitch = null!;

    private FlyoutForm? _scanFlyout, _protFlyout;
    private FlyoutForm? _openFlyout;
    private Control? _openParent;
    private readonly System.Windows.Forms.Timer _hoverTimer;

    public TrayMenuForm(bool dark, Image? logo, IReadOnlyDictionary<string, Image>? icons = null)
    {
        _logoImage = logo;
        _icons = icons;
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

        _hoverTimer = new System.Windows.Forms.Timer { Interval = 220 };
        _hoverTimer.Tick += (_, _) => HoverTick();

        BuildUi();
    }

    protected override bool ShowWithoutActivation => false;
    protected override CreateParams CreateParams
    {
        get { var cp = base.CreateParams; cp.ClassStyle |= 0x00020000 ; return cp; }
    }

    private void BuildUi()
    {
        FormBorderStyle = FormBorderStyle.None;
        ShowInTaskbar = false;
        TopMost = true;
        StartPosition = FormStartPosition.Manual;
        Width = 268;
        BackColor = _bg;
        DoubleBuffered = true;
        Font = new Font("Segoe UI", 9f);

        int y = 0;

        var header = new Panel { Location = new Point(0, y), Size = new Size(Width, 58), BackColor = _surface };
        header.Paint += (_, e) =>
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            e.Graphics.InterpolationMode = InterpolationMode.HighQualityBicubic;
            var dstRect = new Rectangle(14, 12, Width - 28, header.Height - 24);
            if (_logoImage != null)
            {
                var srcRatio = (float)_logoImage.Width / _logoImage.Height;
                int w = (int)(dstRect.Height * srcRatio);
                var final = new Rectangle(dstRect.X + (dstRect.Width - w) / 2, dstRect.Y, w, dstRect.Height);
                e.Graphics.DrawImage(_logoImage, final);
            }
        };
        Controls.Add(header);
        y += header.Height + 6;

        y = AddMenuItem(y, Loc.T("Otwórz Malward"), "url", _ => { Close(); OnOpen?.Invoke(); });
        y = AddFlyoutItem(y, Loc.T("Skanuj"), "search", () => _scanFlyout);
        y = AddMenuItem(y, Loc.T("Aktualizuj bazy"), "refresh", _ => { Close(); OnUpdate?.Invoke(); });
        y = AddMenuItem(y, Loc.T("Kwarantanna"), "chest", _ => { Close(); OnQuarantine?.Invoke(); });
        y = AddFlyoutItem(y, Loc.T("Zarządzaj osłony"), "shield", () => _protFlyout);

        y = AddSeparator(y);
        y = AddMenuItem(y, Loc.T("Zakończ"), null, _ => { Close(); OnExit?.Invoke(); });
        y = AddSeparator(y);

        _footerLbl = new Label
        {
            ForeColor = _sub, Font = new Font("Segoe UI", 8f),
            Location = new Point(16, y + 6), AutoSize = false, Size = new Size(Width - 32, 30),
            Text = Loc.T("Wczytywanie…"),
        };
        Controls.Add(_footerLbl);
        y += 40;

        Height = y;
        Paint += (_, e) => ControlPaint.DrawBorder(e.Graphics, ClientRectangle, _border, ButtonBorderStyle.Solid);
        Deactivate += (_, _) => ScheduleCloseCheck();

        BuildScanFlyout();
        BuildProtectionFlyout();
    }

    private Button MakeRow(int y, string text, string? iconKey, bool chevron, int height)
    {
        var btn = new Button
        {
            Text = (iconKey != null ? "        " : "  ") + text,
            TextAlign = ContentAlignment.MiddleLeft,
            FlatStyle = FlatStyle.Flat,
            BackColor = _bg, ForeColor = _fg,
            Font = new Font("Segoe UI", 9.5f),
            Location = new Point(8, y), Size = new Size(Width - 16, height),
            Cursor = Cursors.Hand, TabStop = false,
            ImageAlign = ContentAlignment.MiddleLeft,
            Padding = new Padding(2, 0, 0, 0),
        };
        btn.FlatAppearance.BorderSize = 0;
        btn.FlatAppearance.MouseOverBackColor = _surface;
        if (iconKey != null && _icons != null && _icons.TryGetValue(iconKey, out var img))
            btn.Image = TintIcon(img, _fg, 18);
        if (chevron)
            btn.Paint += (_, e) =>
            {
                using var pen = new Pen(_sub, 1.6f) { StartCap = LineCap.Round, EndCap = LineCap.Round };
                int cx = btn.Width - 18, cy = btn.Height / 2;
                e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
                e.Graphics.DrawLines(pen, new[] { new Point(cx, cy - 4), new Point(cx + 4, cy), new Point(cx, cy + 4) });
            };
        Controls.Add(btn);
        return btn;
    }

    private int AddMenuItem(int y, string text, string? iconKey, Action<EventArgs> click)
    {
        var btn = MakeRow(y, text, iconKey, chevron: false, height: 36);
        btn.Click += (_, e) => click(e);
        btn.MouseEnter += (_, _) => CloseFlyoutSoon();
        return y + 38;
    }

    private int AddFlyoutItem(int y, string text, string iconKey, Func<FlyoutForm?> flyout)
    {
        var btn = MakeRow(y, text, iconKey, chevron: true, height: 36);
        btn.MouseEnter += (_, _) => OpenFlyout(flyout(), btn);
        btn.Click += (_, _) => OpenFlyout(flyout(), btn);
        return y + 38;
    }

    private int AddSeparator(int y)
    {
        Controls.Add(new Label
        {
            Location = new Point(12, y + 4), Size = new Size(Width - 24, 1), BackColor = _border,
        });
        return y + 8;
    }

    private void BuildScanFlyout()
    {
        _scanFlyout = NewFlyout(228);
        int y = 6;
        y = AddFlyoutAction(_scanFlyout, y, Loc.T("Szybkie skanowanie"), () => { CloseAll(); OnQuickScan?.Invoke(); });
        y = AddFlyoutAction(_scanFlyout, y, Loc.T("Pełne skanowanie"),    () => { CloseAll(); OnFullScan?.Invoke(); });
        y = AddFlyoutAction(_scanFlyout, y, Loc.T("Wybierz folder…"),     () => { CloseAll(); OnCustomScan?.Invoke(); });
        _scanFlyout.Height = y + 6;
    }

    private void BuildProtectionFlyout()
    {
        _protFlyout = NewFlyout(286);
        int y = 8;
        _residentSwitch  = AddCheckRow(_protFlyout, y, Loc.T("Ochrona rezydentna"), on => OnToggleResident?.Invoke(on));  y += 38;
        _networkSwitch   = AddCheckRow(_protFlyout, y, Loc.T("Osłona sieciowa"),    on => OnToggleNetwork?.Invoke(on));   y += 38;
        _backupSwitch    = AddCheckRow(_protFlyout, y, Loc.T("Kopia zapasowa"),     on => OnToggleBackup?.Invoke(on));    y += 38;
        _snapshotsSwitch = AddCheckRow(_protFlyout, y, Loc.T("Migawki plików"),     on => OnToggleSnapshots?.Invoke(on)); y += 38;
        _removableSwitch = AddCheckRow(_protFlyout, y, Loc.T("Autoskan nośników"),  on => OnToggleRemovable?.Invoke(on)); y += 38;
        _protFlyout.Height = y + 6;
    }

    private FlyoutForm NewFlyout(int width)
    {
        var f = new FlyoutForm(_bg, _border)
        {
            Width = width,
            Font = new Font("Segoe UI", 9f),
        };
        f.MouseEnteredContent += () => _hoverTimer.Stop();
        f.MouseLeftContent += CloseFlyoutSoon;
        f.Deactivate += (_, _) => ScheduleCloseCheck();
        return f;
    }

    private int AddFlyoutAction(FlyoutForm f, int y, string text, Action click)
    {
        var btn = new Button
        {
            Text = "   " + text,
            TextAlign = ContentAlignment.MiddleLeft,
            FlatStyle = FlatStyle.Flat,
            BackColor = _bg, ForeColor = _fg,
            Font = new Font("Segoe UI", 9.5f),
            Location = new Point(6, y), Size = new Size(f.Width - 12, 32),
            Cursor = Cursors.Hand, TabStop = false,
        };
        btn.FlatAppearance.BorderSize = 0;
        btn.FlatAppearance.MouseOverBackColor = _surface;
        btn.Click += (_, _) => click();
        f.Host.Controls.Add(btn);
        return y + 34;
    }

    private CheckRow AddCheckRow(FlyoutForm f, int y, string name, Action<bool> toggle)
    {
        var row = new CheckRow(name, _fg, CheckBlue)
        {
            BackColor = _bg,
            Location = new Point(6, y),
            Size = new Size(f.Width - 12, 34),
        };
        row.FlatAppearance.MouseOverBackColor = _surface;
        row.UserToggled += on => toggle(on);
        f.Host.Controls.Add(row);
        return row;
    }

    private void OpenFlyout(FlyoutForm? f, Control parent)
    {
        _hoverTimer.Stop();
        if (f == null) return;
        if (_openFlyout == f) { _openParent = parent; return; }
        _openFlyout?.Hide();
        _openFlyout = f;
        _openParent = parent;

        var area = Screen.FromControl(this).WorkingArea;
        int top = Math.Min(Top + parent.Top - 2, area.Bottom - f.Height - 4);
        top = Math.Max(area.Top + 4, top);
        int left = Left - f.Width + 2;
        if (left < area.Left + 4) left = Right - 2;
        f.Location = new Point(left, top);
        f.ShowInactive();
    }

    private void CloseFlyoutSoon() => _hoverTimer.Start();

    private void HoverTick()
    {
        _hoverTimer.Stop();
        if (_openFlyout == null) return;
        var p = Cursor.Position;
        bool overFlyout = _openFlyout.Bounds.Contains(p);
        bool overParent = _openParent != null &&
            new Rectangle(_openParent.PointToScreen(Point.Empty), _openParent.Size).Contains(p);
        if (!overFlyout && !overParent)
        {
            _openFlyout.Hide();
            _openFlyout = null; _openParent = null;
        }
    }

    private void ScheduleCloseCheck()
    {
        BeginInvoke(new Action(() =>
        {
            var af = Form.ActiveForm;
            if (af != this && af != _scanFlyout && af != _protFlyout)
                CloseAll();
        }));
    }

    private void CloseAll()
    {
        try { _scanFlyout?.Hide(); _protFlyout?.Hide(); } catch { }
        Close();
    }

    public void SetStatus(
        bool residentAvailable, bool residentEnabled, bool residentRunning,
        bool networkAvailable,  bool networkEnabled,  bool networkRunning,
        string lastUpdate, string version, string dbVersion = "—")
    {
        _residentAvailable = residentAvailable; _residentEnabled = residentEnabled; _residentRunning = residentRunning;
        _networkAvailable  = networkAvailable;  _networkEnabled  = networkEnabled;  _networkRunning  = networkRunning;
        _lastUpdate = lastUpdate; _version = version; _dbVersion = dbVersion;
        RefreshControls();
    }

    public void SetToggleStates(
        bool backupAvailable, bool backupOn,
        bool snapshotsAvailable, bool snapshotsOn,
        bool removableAvailable, bool removableOn)
    {
        _backupAvailable = backupAvailable;       _backupOn = backupOn;
        _snapshotsAvailable = snapshotsAvailable; _snapshotsOn = snapshotsOn;
        _removableAvailable = removableAvailable; _removableOn = removableOn;
        RefreshControls();
    }

    private void RefreshControls()
    {
        _residentSwitch.Enabled = _residentAvailable;
        _networkSwitch.Enabled  = _networkAvailable;
        _residentSwitch.SetCheckedSilent(_residentAvailable && _residentEnabled && _residentRunning);
        _networkSwitch.SetCheckedSilent(_networkAvailable  && _networkEnabled  && _networkRunning);

        _backupSwitch.Enabled    = _backupAvailable;
        _snapshotsSwitch.Enabled = _snapshotsAvailable;
        _removableSwitch.Enabled = _removableAvailable;
        _backupSwitch.SetCheckedSilent(_backupAvailable && _backupOn);
        _snapshotsSwitch.SetCheckedSilent(_snapshotsAvailable && _snapshotsOn);
        _removableSwitch.SetCheckedSilent(_removableAvailable && _removableOn);

        _footerLbl.Text = Loc.F("Ostatnia aktualizacja baz: {0}\nBaza wirusów: {1}\nWersja: {2}",
            _lastUpdate, _dbVersion, _version);
    }

    public void ShowAtCursor()
    {
        var cur = Cursor.Position;
        var area = Screen.PrimaryScreen?.WorkingArea ?? new Rectangle(0, 0, 1920, 1080);
        int x = Math.Min(cur.X - Width / 2, area.Right - Width - 4);
        int y = cur.Y - Height - 4;
        if (y < area.Top) y = cur.Y + 8;
        Location = new Point(Math.Max(area.Left + 4, x), Math.Max(area.Top + 4, y));
        Show();
        Activate();
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        try { _scanFlyout?.Dispose(); _protFlyout?.Dispose(); _hoverTimer.Dispose(); } catch { }
        base.OnFormClosed(e);
    }

    private static Bitmap TintIcon(Image src, Color color, int size)
    {
        var bmp = new Bitmap(size, size);
        using var g = Graphics.FromImage(bmp);
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.InterpolationMode = InterpolationMode.HighQualityBicubic;
        var cm = new ColorMatrix(new[]
        {
            new float[] {0,0,0,0,0},
            new float[] {0,0,0,0,0},
            new float[] {0,0,0,0,0},
            new float[] {0,0,0,1,0},
            new[] { color.R / 255f, color.G / 255f, color.B / 255f, 0, 1 },
        });
        using var attr = new ImageAttributes();
        attr.SetColorMatrix(cm);
        g.DrawImage(src, new Rectangle(0, 0, size, size),
            0, 0, src.Width, src.Height, GraphicsUnit.Pixel, attr);
        return bmp;
    }

    private sealed class FlyoutForm : Form
    {
        public Panel Host { get; }
        public event Action? MouseEnteredContent;
        public event Action? MouseLeftContent;
        private readonly Color _border;

        public FlyoutForm(Color bg, Color border)
        {
            _border = border;
            FormBorderStyle = FormBorderStyle.None;
            ShowInTaskbar = false;
            TopMost = true;
            StartPosition = FormStartPosition.Manual;
            BackColor = bg;
            DoubleBuffered = true;
            Host = new Panel { Dock = DockStyle.Fill, BackColor = bg };
            Controls.Add(Host);
            Paint += (_, e) => ControlPaint.DrawBorder(e.Graphics, ClientRectangle, _border, ButtonBorderStyle.Solid);
            Host.MouseEnter += (_, _) => MouseEnteredContent?.Invoke();
            Host.MouseLeave += (_, _) => MouseLeftContent?.Invoke();
            MouseEnter += (_, _) => MouseEnteredContent?.Invoke();
            MouseLeave += (_, _) => MouseLeftContent?.Invoke();
        }

        protected override bool ShowWithoutActivation => true;
        protected override CreateParams CreateParams
        {
            get { var cp = base.CreateParams; cp.ClassStyle |= 0x00020000 ; return cp; }
        }

        public void ShowInactive() => Show();
    }

    private sealed class CheckRow : Button
    {
        private bool _on;
        private readonly Color _check;
        public event Action<bool>? UserToggled;

        public CheckRow(string name, Color fg, Color check)
        {
            _check = check;
            Text = "        " + name;
            TextAlign = ContentAlignment.MiddleLeft;
            FlatStyle = FlatStyle.Flat;
            ForeColor = fg;
            Font = new Font("Segoe UI", 9.5f);
            Cursor = Cursors.Hand;
            TabStop = false;
            FlatAppearance.BorderSize = 0;
            Click += (_, _) =>
            {
                if (!Enabled) return;
                _on = !_on;
                Invalidate();
                UserToggled?.Invoke(_on);
            };
        }

        public void SetCheckedSilent(bool on) { _on = on; Invalidate(); }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            if (!_on) return;
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using var pen = new Pen(_check, 2.2f)
            { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round };
            int cy = Height / 2, x = 12;
            g.DrawLines(pen, new[]
            {
                new Point(x, cy + 1),
                new Point(x + 4, cy + 5),
                new Point(x + 11, cy - 5),
            });
        }
    }
}
