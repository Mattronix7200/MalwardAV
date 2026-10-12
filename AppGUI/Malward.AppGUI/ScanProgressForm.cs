using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Drawing.Text;
using System.IO;
using System.Windows.Forms;
using Malward.AppGUI.Services;

namespace Malward.AppGUI;

public sealed class ScanProgressForm : Form
{
    public enum Mode
    {
        Running,
        FinishedClean,
        FinishedThreats,
        RemovableRunning,
        RemovableFinished,
        Updating,
        UpdatingFinished,
    }

    public Action? OnOpenMainWindow;

    private readonly bool _dark;
    private Mode _mode = Mode.Running;

    private string _headline = "Skanowanie w toku";
    private int _pct = -1;
    private bool _showPct = true;

    private readonly Color _bg, _fg, _sub, _surface, _border;
    private static readonly Color Green  = Color.FromArgb(0x2F, 0xAF, 0x5A);
    private static readonly Color Red    = Color.FromArgb(0xC4, 0x2B, 0x2B);
    private static readonly Color Accent = Color.FromArgb(0x2E, 0x97, 0xF0);

    private const int M = 16;
    private const int W = 380;
    private const int TitleH = 32;
    private const int HeadH  = 96;

    private Bitmap? _logo;
    private Bitmap? _icoScan;
    private Bitmap? _icoUpdate;
    private BufferedPanel _headPanel = null!;
    private Label _lblFile = null!, _lblCount = null!;
    private Button _btnOpen = null!;
    private System.Windows.Forms.Timer? _autoDismiss;

    public ScanProgressForm(bool dark, AssetPack? assets = null)
    {
        _dark = dark;
        if (dark)
        {
            _bg = Color.FromArgb(0x16, 0x1B, 0x22); _fg = Color.FromArgb(0xE9, 0xEC, 0xF0);
            _sub = Color.FromArgb(0x9C, 0xA3, 0xAF); _surface = Color.FromArgb(0x1C, 0x23, 0x2C);
            _border = Color.FromArgb(0x2B, 0x33, 0x3E);
        }
        else
        {
            _bg = Color.White; _fg = Color.FromArgb(0x0E, 0x11, 0x16);
            _sub = Color.FromArgb(0x6A, 0x72, 0x80); _surface = Color.White;
            _border = Color.FromArgb(0xD7, 0xDC, 0xE2);
        }

        _logo      = LoadAsset(assets, "assets/logo.png");
        _icoScan   = LoadAsset(assets, "assets/g9.png");
        _icoUpdate = LoadAsset(assets, "assets/g2.png");
        BuildUi();
        ApplyMode(Mode.Running, "Skanowanie w toku");
    }

    protected override bool ShowWithoutActivation => true;

    private static Bitmap? LoadAsset(AssetPack? assets, string key)
    {
        try
        {
            if (assets != null && assets.TryGet(key, out var data) && data.Length > 0)
            {
                using var ms = new MemoryStream(data);
                using var tmp = Image.FromStream(ms);
                return new Bitmap(tmp);
            }
        }
        catch { }
        return null;
    }

    private void BuildUi()
    {
        FormBorderStyle = FormBorderStyle.None;
        ShowInTaskbar = false;
        TopMost = true;
        StartPosition = FormStartPosition.Manual;
        Width = W;
        BackColor = _bg;
        Font = new Font("Segoe UI", 9f);
        DoubleBuffered = true;

        var titleBar = new BufferedPanel { Dock = DockStyle.Top, Height = TitleH, BackColor = _surface };
        titleBar.Paint += (_, e) => PaintTitleBar(e.Graphics, titleBar.Height);
        var btnX = new Button
        {
            Text = "✕", Dock = DockStyle.Right, Width = 36, FlatStyle = FlatStyle.Flat,
            ForeColor = _sub, BackColor = _surface, TabStop = false, Font = new Font("Segoe UI", 9f),
        };
        btnX.FlatAppearance.BorderSize = 0;
        btnX.FlatAppearance.MouseOverBackColor = _dark ? Color.FromArgb(0x2A, 0x31, 0x3B) : Color.FromArgb(0xEC, 0xEF, 0xF3);
        btnX.Click += (_, _) => Close();
        titleBar.Controls.Add(btnX);

        _headPanel = new BufferedPanel { Dock = DockStyle.Top, Height = HeadH, BackColor = _bg };
        _headPanel.Paint += (_, e) => PaintHeader(e.Graphics, _headPanel.Width, _headPanel.Height);

        var body = new Panel { Dock = DockStyle.Fill, BackColor = _bg };

        _lblCount = new Label
        {
            Text = Loc.F("Przeskanowano: {0}", 0), ForeColor = _sub, Font = new Font("Segoe UI", 8.5f),
            AutoSize = false, Location = new Point(M, 12), Size = new Size(W - 2 * M, 18),
        };
        body.Controls.Add(_lblCount);

        _lblFile = new Label
        {
            Text = "…", ForeColor = _fg, Font = new Font("Consolas", 9f),
            AutoEllipsis = true, AutoSize = false,
            Location = new Point(M, 32), Size = new Size(W - 2 * M, 20),
        };
        body.Controls.Add(_lblFile);

        _btnOpen = new Button
        {
            Text = Loc.T("Otwórz okno Malward"), FlatStyle = FlatStyle.Flat,
            BackColor = Accent, ForeColor = Color.White,
            Location = new Point(M, 60), Size = new Size(W - 2 * M, 30),
            Font = new Font("Segoe UI", 9.5f), Cursor = Cursors.Hand,
        };
        _btnOpen.FlatAppearance.BorderSize = 0;
        _btnOpen.FlatAppearance.MouseOverBackColor = Color.FromArgb(0x1E, 0x86, 0xDF);
        _btnOpen.Click += (_, _) => { OnOpenMainWindow?.Invoke(); Close(); };
        body.Controls.Add(_btnOpen);

        int bodyH = 60 + 30 + 12;
        Height = TitleH + HeadH + bodyH;

        Controls.Add(body);
        Controls.Add(_headPanel);
        Controls.Add(titleBar);

        Paint += (_, e) => ControlPaint.DrawBorder(e.Graphics, ClientRectangle, _border, ButtonBorderStyle.Solid);

        var area = Screen.PrimaryScreen?.WorkingArea ?? new Rectangle(0, 0, 1920, 1080);
        Location = new Point(area.Right - Width - 18, area.Bottom - Height - 18);
    }

    public void UpdateProgress(int pct, int done, string? currentFile)
    {
        if (IsDisposed) return;
        try
        {
            if (_mode != Mode.Running) ApplyMode(Mode.Running, "Skanowanie w toku");
            if (pct >= 0) SetPct(pct);
            _lblCount.Text = Loc.F("Przeskanowano: {0}", done);
            if (!string.IsNullOrEmpty(currentFile)) { _lblFile.Visible = true; _lblFile.Text = currentFile!; }
        }
        catch { }
    }

    public void SetMode(Mode mode, string? subject = null, int threats = 0)
    {
        if (IsDisposed) return;
        switch (mode)
        {
            case Mode.FinishedClean:
                ApplyMode(mode, Loc.T("Skanowanie zakończone"));
                _lblCount.Text = Loc.T("Nie znaleziono zagrożeń. Twój komputer jest czysty.");
                _lblFile.Visible = false;
                _btnOpen.Text = Loc.T("Otwórz okno Malward");
                StartAutoDismiss(8000);
                break;
            case Mode.FinishedThreats:
                ApplyMode(mode, Loc.T("Wykryto zagrożenia!"));
                _lblCount.Text = Loc.F("Znaleziono {0} podejrzanych elementów. Otwórz Malward.", threats);
                _lblFile.Visible = false;
                _btnOpen.Text = Loc.T("Pokaż wyniki");
                StartAutoDismiss(15000);
                break;
            case Mode.RemovableRunning:
                ApplyMode(mode, Loc.T("Skanowanie nośnika"));
                _lblCount.Text = Loc.T("Sprawdzanie plików…");
                _lblFile.Visible = true; _lblFile.Text = subject ?? "—";
                _btnOpen.Text = Loc.T("Otwórz okno Malward");
                _autoDismiss?.Stop();
                break;
            case Mode.RemovableFinished:
                if (threats > 0)
                {
                    ApplyMode(Mode.FinishedThreats, Loc.T("Wykryto zagrożenia na nośniku!"));
                    _lblCount.Text = Loc.F("Na {0} znaleziono {1} elementów.", subject ?? Loc.T("nośniku"), threats);
                    _btnOpen.Text = Loc.T("Pokaż wyniki");
                    StartAutoDismiss(15000);
                }
                else
                {
                    ApplyMode(Mode.FinishedClean, Loc.T("Nośnik bezpieczny"));
                    _lblCount.Text = Loc.F("Skan {0} zakończony — bez zagrożeń.", subject ?? Loc.T("nośnika"));
                    StartAutoDismiss(8000);
                }
                _lblFile.Visible = false;
                break;
            case Mode.Updating:
                ApplyMode(mode, Loc.T("Aktualizacja w toku"));
                _lblCount.Text = subject ?? Loc.T("Pobieranie bazy danych wirusów w trakcie…");
                _lblFile.Visible = false;
                _btnOpen.Text = Loc.T("Otwórz okno Malward");
                _autoDismiss?.Stop();
                break;
            case Mode.UpdatingFinished:
                ApplyMode(mode, "Bazy zaktualizowane");
                _lblCount.Text = Loc.T("Sygnatury wirusów są aktualne.");
                _lblFile.Visible = false;
                _btnOpen.Text = Loc.T("Otwórz okno Malward");
                StartAutoDismiss(7000);
                break;
            case Mode.Running:
            default:
                ApplyMode(Mode.Running, "Skanowanie w toku");
                if (!string.IsNullOrEmpty(subject)) { _lblFile.Visible = true; _lblFile.Text = subject!; }
                break;
        }
    }

    public void UpdateProgressDownload(int pct, string? phase, string? msg)
    {
        if (IsDisposed) return;
        try
        {
            if (_mode != Mode.Updating) ApplyMode(Mode.Updating, Loc.T("Aktualizacja w toku"));
            if (pct >= 0) SetPct(pct);
            _lblCount.Text = !string.IsNullOrEmpty(msg) ? msg!
                           : !string.IsNullOrEmpty(phase) ? $"Pobieranie: {phase}…"
                           : Loc.T("Pobieranie bazy danych wirusów w trakcie…");
            _lblFile.Visible = false;
        }
        catch { }
    }

    public void UpdateRemovableProgress(int pct, int done, int total, string? file, string? root)
    {
        if (IsDisposed) return;
        try
        {
            if (_mode != Mode.RemovableRunning) ApplyMode(Mode.RemovableRunning, Loc.T("Skanowanie nośnika"));
            if (pct >= 0) SetPct(pct);
            _lblCount.Text = total > 0 ? Loc.F("Przeskanowano: {0} / {1}", done, total) : Loc.F("Przeskanowano: {0}", done);
            _lblFile.Visible = true;
            _lblFile.Text = string.IsNullOrEmpty(file) ? (root ?? "—") : file!;
        }
        catch { }
    }

    private void SetPct(int pct)
    {
        _pct = Math.Max(0, Math.Min(100, pct));
        _headPanel.Invalidate();
    }

    private void ApplyMode(Mode mode, string headline)
    {
        _mode = mode;
        _headline = headline;
        _showPct = mode is Mode.Running or Mode.Updating or Mode.RemovableRunning;
        if (!_showPct) _pct = 100;
        _headPanel.Invalidate();
    }

    private Color BandColor() => _mode switch
    {
        Mode.FinishedClean or Mode.UpdatingFinished => Green,
        Mode.FinishedThreats                        => Red,
        _                                           => Accent,
    };

    private void StartAutoDismiss(int ms)
    {
        try { _autoDismiss?.Stop(); _autoDismiss?.Dispose(); } catch { }
        _autoDismiss = new System.Windows.Forms.Timer { Interval = ms };
        _autoDismiss.Tick += (_, _) => { _autoDismiss?.Stop(); Close(); };
        _autoDismiss.Start();
    }

    private void PaintTitleBar(Graphics g, int h)
    {
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.InterpolationMode = InterpolationMode.HighQualityBicubic;
        g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
        int x = 12;
        if (_logo != null)
        {
            int lh = 18, lw = Math.Max(1, lh * _logo.Width / _logo.Height);
            g.DrawImage(_logo, new Rectangle(x, (h - lh) / 2, lw, lh));
            x += lw + 8;
        }
        else
        {
            using var fb = new Font("Segoe UI", 10f, FontStyle.Bold);
            TextRenderer.DrawText(g, "Malward", fb, new Point(x, (h - 18) / 2), _fg, TextFormatFlags.NoPadding);
            x += TextRenderer.MeasureText("Malward", fb).Width + 8;
        }
        using var fc = new Font("Segoe UI", 8.5f);
        TextRenderer.DrawText(g, Loc.T("Community Edition"), fc, new Point(x, (h - 15) / 2), _sub, TextFormatFlags.NoPadding);
    }

    private void PaintHeader(Graphics g, int w, int h)
    {
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;

        Color band = BandColor();

        int topCut = (int)(w * 0.72), botCut = (int)(w * 0.52);
        using (var path = new GraphicsPath())
        {
            path.AddPolygon(new[]
            {
                new Point(0, 0), new Point(topCut, 0),
                new Point(botCut, h), new Point(0, h),
            });
            using var br = new SolidBrush(band);
            g.FillPath(br, path);
        }

        PaintBigIcon(g, w, h, band);

        using var white = new SolidBrush(Color.White);
        if (_showPct && _pct >= 0)
        {
            using var fTitle = new Font("Segoe UI", 11f, FontStyle.Regular);
            using var fPct   = new Font("Segoe UI", 30f, FontStyle.Bold);
            g.DrawString(_headline, fTitle, white, new PointF(M - 2, 14f));
            g.DrawString($"{_pct} %", fPct, white, new PointF(M - 4, 36f));
        }
        else
        {
            using var fHead = new Font("Segoe UI", 13f, FontStyle.Bold);
            var area = new RectangleF(M - 2, 0, w * 0.52f - M, h);
            using var fmt = new StringFormat { LineAlignment = StringAlignment.Center, Trimming = StringTrimming.None };
            g.DrawString(_headline, fHead, white, area, fmt);
        }
    }

    private void PaintBigIcon(Graphics g, int w, int h, Color band)
    {
        float cx = w * 0.83f, cy = h * 0.5f;

        bool finished = !_showPct;
        Color ink = finished ? Color.FromArgb(225, band) : Color.FromArgb(120, band);
        using var pen = new Pen(ink, 4f) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round };

        switch (_mode)
        {
            case Mode.FinishedClean:
            case Mode.UpdatingFinished:
                g.DrawLines(pen, new[]
                {
                    new PointF(cx - 16, cy + 1), new PointF(cx - 5, cy + 12), new PointF(cx + 17, cy - 14),
                });
                break;
            case Mode.FinishedThreats:
                g.DrawLine(pen, cx - 15, cy - 15, cx + 15, cy + 15);
                g.DrawLine(pen, cx + 15, cy - 15, cx - 15, cy + 15);
                break;
            case Mode.Updating:
                if (_icoUpdate != null) DrawIcon(g, _icoUpdate, cx, cy);
                else PaintGlobeDownload(g, pen, cx, cy);
                break;
            default:
                if (_icoScan != null) DrawIcon(g, _icoScan, cx, cy);
                else PaintMagnifier(g, pen, cx, cy);
                break;
        }
    }

    private static void DrawIcon(Graphics g, Bitmap img, float cx, float cy)
    {
        const float box = 58f, alpha = 0.92f;
        float scale = Math.Min(box / img.Width, box / img.Height);
        float w = img.Width * scale, h = img.Height * scale;
        var rect = Rectangle.Round(new RectangleF(cx - w / 2f, cy - h / 2f, w, h));
        g.InterpolationMode = InterpolationMode.HighQualityBicubic;
        var cm = new ColorMatrix { Matrix33 = alpha };
        using var ia = new ImageAttributes();
        ia.SetColorMatrix(cm);
        g.DrawImage(img, rect, 0, 0, img.Width, img.Height, GraphicsUnit.Pixel, ia);
    }

    private static void PaintMagnifier(Graphics g, Pen pen, float cx, float cy)
    {
        float r = 14f, ox = -4f, oy = -4f;
        g.DrawEllipse(pen, cx - r + ox, cy - r + oy, 2 * r, 2 * r);
        float hx = cx + ox + r * 0.7f, hy = cy + oy + r * 0.7f;
        g.DrawLine(pen, hx, hy, hx + 12, hy + 12);
    }

    private static void PaintGlobeDownload(Graphics g, Pen pen, float cx, float cy)
    {
        float r = 15f, gx = cx - 4f, gy = cy - 5f;

        g.DrawEllipse(pen, gx - r, gy - r, 2 * r, 2 * r);
        g.DrawEllipse(pen, gx - r * 0.5f, gy - r, r, 2 * r);
        g.DrawLine(pen, gx - r, gy, gx + r, gy);

        float ax = cx + 12f, ay = cy + 6f;
        g.DrawLine(pen, ax, ay - 10, ax, ay + 6);
        g.DrawLines(pen, new[] { new PointF(ax - 6, ay), new PointF(ax, ay + 6), new PointF(ax + 6, ay) });
        g.DrawLines(pen, new[]
        {
            new PointF(ax - 9, ay + 9), new PointF(ax - 9, ay + 13), new PointF(ax + 9, ay + 13), new PointF(ax + 9, ay + 9),
        });
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        try { _autoDismiss?.Dispose(); } catch { }
        try { _logo?.Dispose(); } catch { }
        try { _icoScan?.Dispose(); } catch { }
        try { _icoUpdate?.Dispose(); } catch { }
        base.OnFormClosed(e);
    }

    private sealed class BufferedPanel : Panel
    {
        public BufferedPanel() { DoubleBuffered = true; ResizeRedraw = true; }
    }
}
