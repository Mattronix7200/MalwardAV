namespace Malward.ResidentShield;

public enum AlertSeverity { Low = 1, Medium = 2, High = 3 }

public sealed class Notifier
{
    public void Threat(string title, string file, string detail, AlertSeverity sev)
    {
        string sevTag = sev switch
        {
            AlertSeverity.High   => "CRITICAL",
            AlertSeverity.Medium => "WARNING",
            _                    => "INFO",
        };
        Log.Alert("ALERT", $"[{sevTag}] {title}: {Path.GetFileName(file)} | {detail}");
    }

    public void Action(string action, string file, string detail = "")
    {
        Log.Alert("ACTION", $"{action}: {Path.GetFileName(file)}"
            + (string.IsNullOrEmpty(detail) ? "" : $" | {detail}"));
    }

    public void Info(string message) => Log.Info("INFO", message);

    public void Info(string title, string body)
        => Log.Alert("RESTORED", $"{title} | {body}");
}
