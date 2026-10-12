using System.Diagnostics;
using System.Text;
using Malward.Engine.Util;

namespace Malward.Engine.Repair;

public static class SystemFileRestore
{
    public static RepairOutcome AfterRemoval(string path, RepairOutcome outcome)
    {
        var (restored, detail) = TryRestore(path);
        var note = restored ? $"system-restored: {detail}" : $"system-restore-failed: {detail}";
        Console.Error.WriteLine($"[{(restored ? "i" : "!")}] {Path.GetFileName(path)}: {note}");
        return outcome with { Detail = string.IsNullOrEmpty(outcome.Detail) ? note : $"{outcome.Detail}; {note}" };
    }

    public static (bool Restored, string Detail) TryRestore(string path)
    {
        if (!IsUnderWindows(path)) return (false, "poza katalogiem Windows — nie ma czego odtwarzać");
        try
        {
            var sfc = Path.Combine(Environment.SystemDirectory, "sfc.exe");
            if (!File.Exists(sfc)) return (false, "brak sfc.exe");

            var psi = new ProcessStartInfo(sfc, $"/scanfile=\"{path}\"")
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,

                StandardOutputEncoding = Encoding.Unicode,
            };
            using var p = Process.Start(psi);
            if (p == null) return (false, "nie udało się uruchomić sfc.exe");
            var outTask = p.StandardOutput.ReadToEndAsync();
            if (!p.WaitForExit(180_000))
            {
                try { p.Kill(); } catch { }
                return (false, "sfc: przekroczono czas (3 min)");
            }
            string output = "";
            try { output = outTask.GetAwaiter().GetResult().Replace("\0", "").Trim(); } catch { }

            bool exists = File.Exists(path);
            bool valid = exists && SystemFileCheck.HasValidTrustedSignature(path);
            if (valid) return (true, $"sfc odtworzył plik ze składnicy komponentów (kod {p.ExitCode})");
            if (exists) return (false, $"plik jest, ale bez poprawnego podpisu (sfc kod {p.ExitCode}) — uruchom „sfc /scannow”");
            return (false, $"sfc nie odtworzył pliku (kod {p.ExitCode}) — uruchom „sfc /scannow” albo " +
                           "„DISM /Online /Cleanup-Image /RestoreHealth”" +
                           (output.Length > 0 ? $"; sfc: {Shorten(output)}" : ""));
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    private static bool IsUnderWindows(string path)
    {
        try
        {
            var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            return !string.IsNullOrEmpty(win)
                && Path.GetFullPath(path).StartsWith(win + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    private static string Shorten(string s)
    {
        s = string.Join(" ", s.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Select(l => l.Trim()));
        return s.Length > 160 ? s[..160] + "…" : s;
    }
}
