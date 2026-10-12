using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace Malward.AppGUI;

public sealed class ActionPopupForm : Form
{
    private const int W = 420;
    protected override bool ShowWithoutActivation => true;

    private readonly Color _border;

    public ActionPopupForm(bool dark, string title, string message,
        string primaryText, Action primary,
        string? secondaryText = null, Action? secondary = null,
        int autoDismissSec = 0, byte[]? iconPng = null)
    {
        Color bg     = dark ? Color.FromArgb(0x16, 0x1B, 0x22) : Color.White;
        Color fg     = dark ? Color.FromArgb(0xE9, 0xEC, 0xF0) : Color.FromArgb(0x0E, 0x11, 0x16);
        Color sub    = dark ? Color.FromArgb(0x9C, 0xA3, 0xAF) : Color.FromArgb(0x6A, 0x72, 0x80);
        _border      = dark ? Color.FromArgb(0x2B, 0x33, 0x3E) : Color.FromArgb(0xC9, 0xCF, 0xD6);
        Color accent = Color.FromArgb(0x1E, 0x7A, 0xCC);

        FormBorderStyle = FormBorderStyle.None;
        ShowInTaskbar   = false;
        TopMost         = true;
        StartPosition   = FormStartPosition.Manual;
        BackColor       = bg;
        Width           = W;

        const int pad = 18;
        int cw = W - pad * 2;

        Image? iconImg = iconPng != null ? TryImage(iconPng) : null;
        int titleX = iconImg != null ? pad + 54 : pad;
        int msgY   = iconImg != null ? 66 : 46;
        if (iconImg != null)
            Controls.Add(new PictureBox { Image = iconImg, SizeMode = PictureBoxSizeMode.Zoom,
                Location = new Point(pad, 14), Size = new Size(44, 44), BackColor = Color.Transparent });

        var lblTitle = new Label
        {
            Text = title, ForeColor = fg, AutoSize = false,
            Font = new Font("Segoe UI", 11f, FontStyle.Bold),
            Location = new Point(titleX, 18), Size = new Size(W - pad - titleX, 24),
        };

        int msgH;
        using (var f = new Font("Segoe UI", 9.5f))
            msgH = Math.Max(20, TextRenderer.MeasureText(message, f,
                new Size(cw, 400), TextFormatFlags.WordBreak).Height);

        var lblMsg = new Label
        {
            Text = message, ForeColor = sub, AutoSize = false,
            Font = new Font("Segoe UI", 9.5f),
            Location = new Point(pad, msgY), Size = new Size(cw, msgH),
        };

        int by = msgY + msgH + 14;

        Button MakeBtn(string text, bool primaryStyle, Action onClick)
        {
            var b = new Button
            {
                Text = text, FlatStyle = FlatStyle.Flat, Size = new Size(128, 34),
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                ForeColor = primaryStyle ? Color.White : fg,
                BackColor = primaryStyle ? accent : bg, Cursor = Cursors.Hand,
            };
            b.FlatAppearance.BorderColor = primaryStyle ? accent : _border;
            b.Click += (_, __) => { try { onClick(); } catch { } try { Close(); } catch { } };
            return b;
        }

        Controls.Add(lblTitle);
        Controls.Add(lblMsg);

        var btnPrimary = MakeBtn(primaryText, true, primary);
        btnPrimary.Location = new Point(W - pad - btnPrimary.Width, by);
        Controls.Add(btnPrimary);

        if (secondaryText != null && secondary != null)
        {
            var btnSecondary = MakeBtn(secondaryText, false, secondary);
            btnSecondary.Location = new Point(pad, by);
            Controls.Add(btnSecondary);
        }

        Height = by + 34 + 16;

        var wa = Screen.PrimaryScreen!.WorkingArea;
        Location = new Point(wa.Right - Width - 12, wa.Bottom - Height - 12);
        PopupStackManager.Register(this);

        if (autoDismissSec > 0)
        {
            var t = new System.Windows.Forms.Timer { Interval = autoDismissSec * 1000 };
            t.Tick += (_, __) => { t.Stop(); try { Close(); } catch { } };
            t.Start();
        }
    }

    private static Image? TryImage(byte[] bytes)
    {
        try { using var ms = new MemoryStream(bytes); return Image.FromStream(ms); }
        catch { return null; }
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
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
