using System;
using System.Drawing;
using System.IO;
using System.Windows.Forms;
using Malward.AppGUI.Services;

namespace Malward.AppGUI;

public sealed class FirewallAlertForm : Form
{
    private const int W = 460;
    protected override bool ShowWithoutActivation => true;
    private readonly Color _border;

    public sealed record Info(string AppName, string AppPath, string IpPort, string Reason);

    public FirewallAlertForm(bool dark, Info info, byte[]? firewallIcon, byte[]? logoIcon, Icon? appIcon)
    {
        Color bg   = dark ? Color.FromArgb(0x16, 0x1B, 0x22) : Color.White;
        Color fg   = dark ? Color.FromArgb(0xE9, 0xEC, 0xF0) : Color.FromArgb(0x0E, 0x11, 0x16);
        Color sub  = dark ? Color.FromArgb(0x9C, 0xA3, 0xAF) : Color.FromArgb(0x55, 0x5C, 0x66);
        _border    = dark ? Color.FromArgb(0x2B, 0x33, 0x3E) : Color.FromArgb(0xC9, 0xCF, 0xD6);
        Color head = Color.FromArgb(0xC0, 0x2A, 0x2A);
        Color box  = dark ? Color.FromArgb(0x1C, 0x23, 0x2C) : Color.FromArgb(0xF6, 0xF8, 0xFA);

        FormBorderStyle = FormBorderStyle.None;
        ShowInTaskbar   = false;
        TopMost         = true;
        StartPosition   = FormStartPosition.Manual;
        BackColor       = bg;
        Width           = W;

        int tbH = 34;
        var titleBar = new Panel { BackColor = bg, Location = new Point(0, 0), Size = new Size(W, tbH) };
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
        titleBar.Controls.Add(new Label { Text = Loc.T("Community Edition"), ForeColor = sub,
            Font = new Font("Segoe UI", 8.5f), AutoSize = true, Location = new Point(afterLogo, 10) });
        Controls.Add(titleBar);

        int hb = 52;
        var header = new Panel { BackColor = head, Location = new Point(0, tbH), Size = new Size(W, hb) };
        var fwImg = TryImage(firewallIcon);
        if (fwImg != null)
            header.Controls.Add(new PictureBox { Image = fwImg, SizeMode = PictureBoxSizeMode.Zoom,
                Location = new Point(14, (hb - 28) / 2), Size = new Size(28, 28), BackColor = Color.Transparent });
        header.Controls.Add(new Label { Text = Loc.T("Alert zapory sieciowej"), ForeColor = Color.White,
            Font = new Font("Segoe UI", 12.5f, FontStyle.Bold), AutoSize = false,
            Location = new Point(fwImg != null ? 52 : 14, 0), Size = new Size(W - 60, hb),
            TextAlign = ContentAlignment.MiddleLeft });
        Controls.Add(header);
        int y = tbH + hb;

        Controls.Add(new Label
        {
            Text = Loc.T("Zapora Malward przerwała natychmiastowo połączenie z niebezpiecznym adresem IP " +
                   "z bazy zagrożeń, dzięki czemu jesteś bezpieczny przed atakami. Poniżej znajdziesz " +
                   "dodatkowe informacje."),
            ForeColor = sub, Font = new Font("Segoe UI", 9f), AutoSize = false,
            Location = new Point(16, y + 10), Size = new Size(W - 32, 46),
        });
        y += 62;

        var infoBox = new Panel { BackColor = box, Location = new Point(16, y), Size = new Size(W - 32, 112),
            BorderStyle = BorderStyle.FixedSingle };
        if (appIcon != null)
            infoBox.Controls.Add(new PictureBox { Image = appIcon.ToBitmap(), SizeMode = PictureBoxSizeMode.Zoom,
                Location = new Point(10, 12), Size = new Size(40, 40), BackColor = Color.Transparent });
        infoBox.Controls.Add(new Label { Text = Loc.T("Aplikacja"), ForeColor = sub, Font = new Font("Segoe UI", 8f),
            Location = new Point(6, 54), Size = new Size(52, 16), TextAlign = ContentAlignment.MiddleCenter });
        infoBox.Controls.Add(new Label { Text = info.AppName, ForeColor = fg,
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold), AutoSize = false,
            Location = new Point(64, 10), Size = new Size(W - 32 - 74, 18), AutoEllipsis = true });
        infoBox.Controls.Add(new Label { Text = info.AppPath, ForeColor = sub, Font = new Font("Segoe UI", 8f),
            AutoSize = false, Location = new Point(64, 28), Size = new Size(W - 32 - 74, 16), AutoEllipsis = true });
        infoBox.Controls.Add(new Label { Text = Loc.T("Adres IP / Usługa URL:"), ForeColor = sub,
            Font = new Font("Segoe UI", 8f), Location = new Point(64, 52), Size = new Size(220, 14) });
        infoBox.Controls.Add(new Label { Text = info.IpPort, ForeColor = fg,
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold), Location = new Point(64, 66),
            Size = new Size(W - 32 - 74, 16), AutoEllipsis = true });
        infoBox.Controls.Add(new Label { Text = Loc.T("Powód blokady:"), ForeColor = sub, Font = new Font("Segoe UI", 8f),
            Location = new Point(64, 88), Size = new Size(90, 16) });
        infoBox.Controls.Add(new Label { Text = info.Reason, ForeColor = Color.FromArgb(0xD0, 0x3A, 0x3A),
            Font = new Font("Segoe UI", 8.5f, FontStyle.Bold), Location = new Point(150, 88),
            Size = new Size(W - 32 - 160, 16), AutoEllipsis = true });
        Controls.Add(infoBox);
        y += 122;

        var btn = new Button
        {
            Text = "✓  " + Loc.T("Rozumiem"), Location = new Point(16, y), Size = new Size(W - 32, 36),
            FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 10f, FontStyle.Bold),
            ForeColor = Color.White, BackColor = Color.FromArgb(0x6B, 0x72, 0x80), Cursor = Cursors.Hand,
        };
        btn.FlatAppearance.BorderSize = 0;
        btn.Click += (_, __) => { try { Close(); } catch { } };
        Controls.Add(btn);
        y += 36 + 14;

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
