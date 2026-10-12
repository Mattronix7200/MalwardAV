using System.Drawing;
using System.Windows.Forms;

namespace Malward.Updater;

internal sealed class ProgressForm : Form
{
    private readonly bool _en;
    private readonly Label _phase;
    private readonly Label _pct;
    private readonly Label _message;
    private readonly ProgressBar _bar;
    private readonly Button _close;

    public ProgressForm(bool english)
    {
        _en = english;
        Text = _en ? "Malward — update" : "Malward — aktualizacja";

        try { Icon = Icon.ExtractAssociatedIcon(Environment.ProcessPath ?? Application.ExecutablePath); }
        catch {  }
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false; MinimizeBox = false; ControlBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        ShowInTaskbar = true; TopMost = true;
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(420, 132);
        BackColor = Color.White;
        ForeColor = Color.FromArgb(28, 28, 30);
        Font = new Font("Segoe UI", 9.5f);

        var title = new Label
        {
            Text = _en ? "Installing the Malward update" : "Instalowanie aktualizacji Malward",
            Font = new Font("Segoe UI", 11f, FontStyle.Bold),
            AutoSize = false, Location = new Point(18, 14), Size = new Size(384, 24),
        };
        _phase = new Label
        {
            Text = _en ? "Preparing…" : "Przygotowanie…", AutoSize = false,
            ForeColor = Color.FromArgb(90, 90, 95),
            Location = new Point(18, 42), Size = new Size(330, 18),
        };
        _pct = new Label
        {
            Text = "", AutoSize = false, TextAlign = ContentAlignment.MiddleRight,
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            Location = new Point(348, 42), Size = new Size(54, 18),
        };
        _bar = new ProgressBar
        {
            Location = new Point(18, 64), Size = new Size(384, 14),
            Style = ProgressBarStyle.Marquee, MarqueeAnimationSpeed = 30,
        };
        _message = new Label
        {
            Text = "", AutoSize = false, ForeColor = Color.FromArgb(90, 90, 95),
            Font = new Font("Segoe UI", 8.5f),
            Location = new Point(18, 84), Size = new Size(290, 40),
        };
        _close = new Button
        {
            Text = _en ? "Close" : "Zamknij", Location = new Point(316, 94), Size = new Size(86, 26),
            Visible = false, Enabled = false,
        };
        _close.Click += (_, _) => Close();

        Controls.Add(title); Controls.Add(_phase); Controls.Add(_pct); Controls.Add(_bar);
        Controls.Add(_message); Controls.Add(_close);
    }

    public void Report(string phase, int done, int total)
    {
        if (IsDisposed) return;
        if (InvokeRequired) { try { BeginInvoke(() => Report(phase, done, total)); } catch { } return; }
        _phase.Text = phase;
        if (total > 0)
        {
            _bar.Style = ProgressBarStyle.Continuous;
            _bar.Maximum = total;
            _bar.Value = Math.Clamp(done, 0, total);
            _pct.Text = $"{(int)Math.Round(100.0 * Math.Clamp(done, 0, total) / total)}%";
        }
        else { _bar.Style = ProgressBarStyle.Marquee; _pct.Text = ""; }
    }

    public void Finish(bool ok, string message)
    {
        if (IsDisposed) return;
        if (InvokeRequired) { try { BeginInvoke(() => Finish(ok, message)); } catch { } return; }
        _bar.Style = ProgressBarStyle.Continuous;
        _bar.Maximum = 100;
        _bar.Value = ok ? 100 : Math.Min(_bar.Value, 100);
        _pct.Text = ok ? "100%" : "";
        _phase.Text = ok ? (_en ? "Update complete." : "Aktualizacja zakończona.")
                         : (_en ? "The update failed." : "Aktualizacja nie powiodła się.");
        _phase.ForeColor = ok ? Color.FromArgb(30, 140, 70) : Color.FromArgb(190, 50, 40);
        _message.Text = message;
        if (ok)
        {
            var t = new System.Windows.Forms.Timer { Interval = 1500 };
            t.Tick += (_, _) => { t.Stop(); Close(); };
            t.Start();
        }
        else
        {
            ControlBox = true;
            _close.Visible = true; _close.Enabled = true;
            _close.Focus();
        }
    }
}
