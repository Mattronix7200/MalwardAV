using System.Drawing;
using System.IO;
using System.Windows.Forms;
using Malward.AppGUI.Services;

namespace Malward.AppGUI;

public sealed class FirewallPopupForm : Form
{
    private const int W = 460;
    protected override bool ShowWithoutActivation => true;

    public sealed record Info(string AppName, string AppPath, string Direction, string Protocol,
        string RemoteAddress, string RemotePort, string Pid, string Publisher);

    private readonly Color _border;

    public FirewallPopupForm(bool dark, Info info,
        byte[]? firewallIcon, byte[]? hideIcon, byte[]? logoIcon, Icon? appIcon,
        Action<int> onAllowTemp,
        Action onAllowPerm,
        Action onIgnore,
        Action onBlock,
        Action onWildcard,
        Action<bool> setTrustPublisher)
    {
        Color bg     = dark ? Color.FromArgb(0x16, 0x1B, 0x22) : Color.White;
        Color fg     = dark ? Color.FromArgb(0xE9, 0xEC, 0xF0) : Color.FromArgb(0x0E, 0x11, 0x16);
        Color sub    = dark ? Color.FromArgb(0x9C, 0xA3, 0xAF) : Color.FromArgb(0x55, 0x5C, 0x66);
        _border      = dark ? Color.FromArgb(0x2B, 0x33, 0x3E) : Color.FromArgb(0xC9, 0xCF, 0xD6);
        Color head   = Color.FromArgb(0x5B, 0x7E, 0xA8);
        Color box    = dark ? Color.FromArgb(0x1C, 0x23, 0x2C) : Color.FromArgb(0xF6, 0xF8, 0xFA);
        Color link   = Color.FromArgb(0x1E, 0x7A, 0xCC);
        Color green   = Color.FromArgb(0x1F, 0x2A, 0x22);
        Color redBtn  = Color.FromArgb(0xB0, 0x2A, 0x2A);

        FormBorderStyle = FormBorderStyle.None;
        ShowInTaskbar   = false;
        TopMost         = true;
        StartPosition   = FormStartPosition.Manual;
        BackColor       = bg;
        Width           = W;

        int y = 0;

        int tbH = 34;
        var titleBar = new Panel { BackColor = bg, Location = new Point(0, 0), Size = new Size(W, tbH) };
        var logoImg = logoIcon != null ? TryImage(logoIcon) : null;
        int afterLogo = 12;
        if (logoImg != null)
        {
            int lh = 20, lw = Math.Max(20, (int)Math.Round(logoImg.Width * (lh / (double)logoImg.Height)));
            lw = Math.Min(lw, 150);
            titleBar.Controls.Add(new PictureBox { Image = logoImg, SizeMode = PictureBoxSizeMode.Zoom,
                Location = new Point(12, (tbH - lh) / 2), Size = new Size(lw, lh), BackColor = Color.Transparent });
            afterLogo = 12 + lw + 8;
        }
        else
        {
            titleBar.Controls.Add(new Label { Text = "malward", ForeColor = fg, Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                AutoSize = true, Location = new Point(12, 9) });
            afterLogo = 76;
        }
        titleBar.Controls.Add(new Label { Text = Loc.T("Community Edition"), ForeColor = sub, Font = new Font("Segoe UI", 8.5f),
            AutoSize = true, Location = new Point(afterLogo, 10) });
        Controls.Add(titleBar);

        int hb = 52;
        var header = new Panel { BackColor = head, Location = new Point(0, tbH), Size = new Size(W, hb) };
        var fwImg = firewallIcon != null ? TryImage(firewallIcon) : null;
        if (fwImg != null)
            header.Controls.Add(new PictureBox { Image = fwImg, SizeMode = PictureBoxSizeMode.Zoom,
                Location = new Point(14, (hb - 28) / 2), Size = new Size(28, 28), BackColor = Color.Transparent });
        header.Controls.Add(new Label { Text = Loc.T("Alert zapory sieciowej"), ForeColor = Color.White,
            Font = new Font("Segoe UI", 12.5f, FontStyle.Bold), AutoSize = false,
            Location = new Point(fwImg != null ? 52 : 14, 0), Size = new Size(W - 60, hb), TextAlign = ContentAlignment.MiddleLeft });
        Controls.Add(header);
        y = tbH + hb;

        var desc = new Label
        {
            Text = Loc.T("Zapora sieciowa programu Malward wykryła żądanie aplikacji lub usługi systemowej " +
                   "z zapytaniem o dostęp do sieci. Przejrzyj poniższe informacje, a następnie dokonaj wyboru."),
            ForeColor = sub, Font = new Font("Segoe UI", 9f), AutoSize = false,
            Location = new Point(16, y + 10), Size = new Size(W - 32, 46),
        };
        Controls.Add(desc);
        y += 60;

        var infoBox = new Panel { BackColor = box, Location = new Point(16, y), Size = new Size(W - 32, 116),
            BorderStyle = BorderStyle.FixedSingle };

        if (appIcon != null)
            infoBox.Controls.Add(new PictureBox { Image = appIcon.ToBitmap(), SizeMode = PictureBoxSizeMode.Zoom,
                Location = new Point(10, 12), Size = new Size(40, 40), BackColor = Color.Transparent });
        infoBox.Controls.Add(new Label { Text = Loc.T("Aplikacja"), ForeColor = sub, Font = new Font("Segoe UI", 8f),
            Location = new Point(6, 54), Size = new Size(52, 16), TextAlign = ContentAlignment.MiddleCenter });

        infoBox.Controls.Add(new Label { Text = info.AppName, ForeColor = fg, Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            AutoSize = false, Location = new Point(64, 8), Size = new Size(W - 32 - 74 - 150, 18), AutoEllipsis = true });
        infoBox.Controls.Add(new Label { Text = info.AppPath, ForeColor = sub, Font = new Font("Segoe UI", 8f),
            AutoSize = false, Location = new Point(64, 26), Size = new Size(W - 32 - 74, 16), AutoEllipsis = true });

        var wildcard = new LinkLabel { Text = Loc.T("Utwórz regułę wildcard"), AutoSize = true,
            Font = new Font("Segoe UI", 8f), LinkColor = link, ActiveLinkColor = link,
            LinkBehavior = LinkBehavior.AlwaysUnderline, Cursor = Cursors.Hand };
        wildcard.LinkClicked += (_, __) => { try { onWildcard(); } catch { } Close(); };
        infoBox.Controls.Add(wildcard);
        wildcard.Location = new Point(infoBox.Width - wildcard.Width - 10, 8);

        void Kv(string k, string v, int col, int row)
        {
            int x = 64 + col * ((W - 32 - 74) / 2);
            infoBox.Controls.Add(new Label { Text = k, ForeColor = sub, Font = new Font("Segoe UI", 8f),
                Location = new Point(x, 48 + row * 30), Size = new Size(120, 14) });
            infoBox.Controls.Add(new Label { Text = v, ForeColor = fg, Font = new Font("Segoe UI", 9f, FontStyle.Bold),
                Location = new Point(x, 62 + row * 30), Size = new Size(120, 16), AutoEllipsis = true });
        }
        string dirLabel = info.Direction == "IN" ? Loc.T("Przychodzące (IN)") : Loc.T("Wychodzące (OUT)");
        Kv(Loc.T("Kierunek"), dirLabel, 0, 0);
        Kv(Loc.T("Protokół"), info.Protocol, 1, 0);
        Kv("Zdalny adres", $"{info.RemoteAddress}:{info.RemotePort}", 0, 1);
        Kv(Loc.T("PID"), info.Pid, 1, 1);
        Controls.Add(infoBox);
        y += 126;

        var trust = new CheckBox { AutoSize = false, Location = new Point(16, y), Size = new Size(W - 32, 20),
            ForeColor = fg, Font = new Font("Segoe UI", 8.5f),
            Text = string.IsNullOrEmpty(info.Publisher) ? Loc.T("Zaufaj wydawcy") : Loc.F("Zaufaj wydawcy: {0}", info.Publisher) };
        trust.CheckedChanged += (_, __) => { try { setTrustPublisher(trust.Checked); } catch { } };
        Controls.Add(trust);
        y += 28;

        int aph = 28, apW = 206;
        var allowPanel = new Panel { Location = new Point(16, y), Size = new Size(apW, aph),
            BorderStyle = BorderStyle.FixedSingle, BackColor = bg };
        var combo = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, FlatStyle = FlatStyle.Flat,
            Location = new Point(106, 2), Size = new Size(apW - 108, aph - 6), Font = new Font("Segoe UI", 8.5f),
            BackColor = bg, ForeColor = fg };
        combo.Items.AddRange(new object[] { "15 minut", "1 godzina", "8 godzin", Loc.T("1 dzień") });
        combo.SelectedIndex = 0;
        void DoAllowTemp() { int m = combo.SelectedIndex switch { 1 => 60, 2 => 480, 3 => 1440, _ => 15 };
            try { onAllowTemp(m); } catch { } Close(); }
        var allowLbl = new Label { Text = Loc.T("⏱ Zezwól"), ForeColor = fg, Font = new Font("Segoe UI", 9f),
            Location = new Point(2, 0), Size = new Size(100, aph - 2), TextAlign = ContentAlignment.MiddleCenter,
            Cursor = Cursors.Hand };
        allowLbl.Click += (_, __) => DoAllowTemp();
        var divider = new Panel { BackColor = _border, Location = new Point(104, 3), Size = new Size(1, aph - 8) };
        allowPanel.Controls.Add(allowLbl); allowPanel.Controls.Add(divider); allowPanel.Controls.Add(combo);
        Controls.Add(allowPanel);

        var btnIgnore = MakeBtn("Ignoruj (5 min)", new Point(16 + apW + 8, y), new Size(W - 16 - (16 + apW + 8), aph), fg, bg, false);

        var hImg = hideIcon != null ? ScaledImage(hideIcon, 15) : null;
        if (hImg != null) { btnIgnore.Image = hImg; btnIgnore.ImageAlign = ContentAlignment.MiddleLeft;
            btnIgnore.TextAlign = ContentAlignment.MiddleCenter; btnIgnore.Padding = new Padding(6, 0, 0, 0); }
        btnIgnore.Click += (_, __) => { try { onIgnore(); } catch { } Close(); };
        Controls.Add(btnIgnore);
        y += 34;

        var btnAllow = MakeBtn(Loc.T("✓ Zezwól"), new Point(16, y), new Size((W - 32 - 8) / 2, 32), Color.White, Color.FromArgb(0x2F, 0x7A, 0x3A), true);
        btnAllow.Click += (_, __) => { try { onAllowPerm(); } catch { } Close(); };
        var btnBlock = MakeBtn("⊘ Zablokuj", new Point(16 + (W - 32 - 8) / 2 + 8, y), new Size((W - 32 - 8) / 2, 32), Color.White, redBtn, true);
        btnBlock.Click += (_, __) => { try { onBlock(); } catch { } Close(); };
        Controls.Add(btnAllow); Controls.Add(btnBlock);
        y += 32 + 14;

        Height = y;
        var wa = Screen.PrimaryScreen!.WorkingArea;
        Location = new Point(wa.Right - Width - 12, wa.Bottom - Height - 12);
        PopupStackManager.Register(this);
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
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
            g.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
            g.DrawImage(src, 0, 0, size, size);
            return bmp;
        }
        catch { return null; }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        using var p = new Pen(_border);
        e.Graphics.DrawRectangle(p, 0, 0, Width - 1, Height - 1);
    }
}
