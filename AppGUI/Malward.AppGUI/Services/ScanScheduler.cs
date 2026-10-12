using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;

namespace Malward.AppGUI.Services;

public static class ScanScheduler
{
    public const string TaskName = "MalwardScheduledScan";

    public static async Task<(bool ok, string? error)> ApplyAsync(
        ScanScheduleStore.Schedule s, string? malscanPath)
    {
        if (!s.Enabled) return await DisableAsync();
        if (string.IsNullOrEmpty(malscanPath) || !File.Exists(malscanPath))
            return (false, "Nie znaleziono malscan.exe.");

        var (command, arguments) = BuildExecCommand(s, malscanPath);

        var user = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
        string xml = BuildTaskXml(s, command, arguments, user);

        string tmp = Path.Combine(Path.GetTempPath(), $"malward-task-{System.Guid.NewGuid():N}.xml");
        try
        {
            File.WriteAllText(tmp, xml, new UnicodeEncoding(bigEndian: false, byteOrderMark: true));
        }
        catch (System.Exception ex) { return (false, $"zapis XML: {ex.Message}"); }

        try
        {
            var (rc, output) = await RunSchtasksAsync(new()
            {
                "/Create", "/F",
                "/TN", TaskName,
                "/XML", tmp,
            });
            if (rc == 0) return (true, null);
            return (false, $"schtasks: {output}");
        }
        finally
        {
            try { File.Delete(tmp); } catch { }
        }
    }

    public static async Task<(bool ok, string? error)> DisableAsync()
    {
        var (rc, output) = await RunSchtasksAsync(new() { "/Delete", "/F", "/TN", TaskName });
        if (rc == 0) return (true, null);

        if (output.Contains("ERROR: The system cannot find the file specified", System.StringComparison.OrdinalIgnoreCase)
         || output.Contains("Nie można odnaleźć", System.StringComparison.OrdinalIgnoreCase))
            return (true, null);
        return (false, output);
    }

    private static (string command, string arguments) BuildExecCommand(
        ScanScheduleStore.Schedule s, string malscan)
    {
        var malward = ResolveMalwardExe(malscan);
        var args = new StringBuilder();
        args.Append("--scheduled-scan ");
        args.Append(s.Mode switch { "full" => "full", "custom" => "custom", _ => "quick" });
        if (s.Mode == "custom")
        {
            foreach (var f in s.Folders)
            {
                if (string.IsNullOrWhiteSpace(f)) continue;
                args.Append(" --folder \"").Append(f).Append('"');
            }
        }
        return (malward, args.ToString());
    }

    private static string ResolveMalwardExe(string malscanPath)
    {
        try
        {
            var dir = Path.GetDirectoryName(malscanPath);
            if (!string.IsNullOrEmpty(dir))
            {
                var mw = Path.Combine(dir, "malward.exe");
                if (File.Exists(mw)) return mw;
            }
        }
        catch { }

        return Environment.ProcessPath ?? malscanPath;
    }

    private static string BuildTaskXml(
        ScanScheduleStore.Schedule s, string command, string arguments, string userId)
    {
        XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

        var triggers = new XElement(ns + "Triggers");
        switch (s.Trigger)
        {
            case "logon":
            case "afterupdate":
                triggers.Add(new XElement(ns + "LogonTrigger",
                    new XElement(ns + "Enabled", "true"),
                    new XElement(ns + "UserId", userId)));
                break;
            case "daily":
                triggers.Add(new XElement(ns + "CalendarTrigger",
                    new XElement(ns + "StartBoundary", $"{StartBoundary(s.Time)}"),
                    new XElement(ns + "Enabled", "true"),
                    new XElement(ns + "ScheduleByDay",
                        new XElement(ns + "DaysInterval", "1"))));
                break;
            case "weekly":
                triggers.Add(new XElement(ns + "CalendarTrigger",
                    new XElement(ns + "StartBoundary", $"{StartBoundary(s.Time)}"),
                    new XElement(ns + "Enabled", "true"),
                    new XElement(ns + "ScheduleByWeek",
                        new XElement(ns + "DaysOfWeek", new XElement(ns + DayElementName(s.Day))),
                        new XElement(ns + "WeeksInterval", "1"))));
                break;
            default:
                triggers.Add(new XElement(ns + "LogonTrigger",
                    new XElement(ns + "Enabled", "true"),
                    new XElement(ns + "UserId", userId)));
                break;
        }

        var principal = new XElement(ns + "Principal",
            new XAttribute("id", "Author"),
            new XElement(ns + "UserId", userId),
            new XElement(ns + "LogonType", "InteractiveToken"),
            new XElement(ns + "RunLevel", "HighestAvailable"));

        var exec = new XElement(ns + "Exec",
            new XElement(ns + "Command", command));
        if (!string.IsNullOrEmpty(arguments))
            exec.Add(new XElement(ns + "Arguments", arguments));

        var task = new XElement(ns + "Task",
            new XAttribute("version", "1.2"),
            new XAttribute(XNamespace.Xmlns + "xsi", "http://www.w3.org/2001/XMLSchema-instance"),
            new XElement(ns + "RegistrationInfo",
                new XElement(ns + "Description", "Malward — okresowe skanowanie komputera"),
                new XElement(ns + "Author", "Malward")),
            triggers,
            new XElement(ns + "Principals", principal),
            new XElement(ns + "Settings",
                new XElement(ns + "MultipleInstancesPolicy", "IgnoreNew"),
                new XElement(ns + "DisallowStartIfOnBatteries", "false"),
                new XElement(ns + "StopIfGoingOnBatteries", "false"),
                new XElement(ns + "AllowHardTerminate", "true"),
                new XElement(ns + "StartWhenAvailable", "true"),
                new XElement(ns + "RunOnlyIfNetworkAvailable", "false"),
                new XElement(ns + "Enabled", "true"),
                new XElement(ns + "AllowStartOnDemand", "true"),
                new XElement(ns + "Hidden", "false"),
                new XElement(ns + "RunOnlyIfIdle", "false"),
                new XElement(ns + "WakeToRun", "false"),
                new XElement(ns + "Priority", "7")),
            new XElement(ns + "Actions",
                new XAttribute("Context", "Author"),
                exec));

        var doc = new XDocument(new XDeclaration("1.0", "UTF-16", null), task);
        var sw = new StringWriter();
        using (var writer = XmlWriter.Create(sw, new XmlWriterSettings { Indent = true, Encoding = Encoding.Unicode }))
            doc.Save(writer);
        return sw.ToString();
    }

    private static string StartBoundary(string time)
    {
        var t = NormalizeTime(time);
        var parts = t.Split(':');
        int hh = int.Parse(parts[0]);
        int mm = int.Parse(parts[1]);
        var first = System.DateTime.Today.AddDays(1).AddHours(hh).AddMinutes(mm);

        return first.ToString("yyyy-MM-ddTHH:mm:ss");
    }

    private static string NormalizeTime(string t)
    {
        if (string.IsNullOrEmpty(t) || !t.Contains(':')) return "03:00";
        var parts = t.Split(':');
        if (parts.Length < 2) return "03:00";
        int.TryParse(parts[0], out int hh);
        int.TryParse(parts[1], out int mm);
        return $"{Clamp(hh, 0, 23):D2}:{Clamp(mm, 0, 59):D2}";
    }

    private static int Clamp(int v, int lo, int hi) => v < lo ? lo : (v > hi ? hi : v);

    private static string DayElementName(string day) => day?.ToUpperInvariant() switch
    {
        "MON" => "Monday",
        "TUE" => "Tuesday",
        "WED" => "Wednesday",
        "THU" => "Thursday",
        "FRI" => "Friday",
        "SAT" => "Saturday",
        "SUN" => "Sunday",
        _     => "Monday",
    };

    private static async Task<(int rc, string output)> RunSchtasksAsync(System.Collections.Generic.List<string> args)
    {
        try
        {
            var psi = new ProcessStartInfo("schtasks.exe")
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            foreach (var a in args) psi.ArgumentList.Add(a);
            using var p = Process.Start(psi);
            if (p == null) return (-1, "nie uruchomiono schtasks.exe");
            string o = await p.StandardOutput.ReadToEndAsync();
            string e = await p.StandardError.ReadToEndAsync();
            await p.WaitForExitAsync();
            return (p.ExitCode, string.IsNullOrWhiteSpace(e) ? o : e);
        }
        catch (System.Exception ex) { return (-1, ex.Message); }
    }
}
