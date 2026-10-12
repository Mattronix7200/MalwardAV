using System.Diagnostics;
using Malward.Engine.Util;

namespace Malward.Engine.Heuristic;

public sealed class HeurScannerRunner
{
    private readonly int _timeoutSec;

    private static readonly SemaphoreSlim Slots =
        new(Math.Clamp(Environment.ProcessorCount / 2, 1, 4));

    public HeurScannerRunner(int timeoutSec) { _timeoutSec = Math.Max(5, timeoutSec); }

    public sealed record HeurResult(bool Detected, string? RuleName, string? Error);

    public HeurResult Scan(string yacPath, string filePath)
    {
        var exe = EmbeddedHeurScanner.EnsureExtracted();
        if (string.IsNullOrEmpty(exe) || !File.Exists(exe))
            return new HeurResult(false, null, "Heuristic scanner unavailable (no embedded or loose heurscanner.exe)");
        if (!File.Exists(yacPath))
            return new HeurResult(false, null, $"Rules not found at {yacPath}");

        var psi = new ProcessStartInfo
        {
            FileName = exe,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("-C");
        psi.ArgumentList.Add(yacPath);
        psi.ArgumentList.Add(filePath);

        Slots.Wait();
        try
        {
            using var p = Process.Start(psi)!;
            string stdout = p.StandardOutput.ReadToEnd();
            string stderr = p.StandardError.ReadToEnd();
            if (!p.WaitForExit(_timeoutSec * 1000))
            {
                try { p.Kill(true); } catch { }
                return new HeurResult(false, null, "Timeout");
            }

            foreach (var rawLine in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var line = rawLine.Trim();
                if (line.Length == 0) continue;
                var parts = line.Split(new[] { ' ', '\t' }, 2, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 1 && !string.IsNullOrWhiteSpace(parts[0]))
                    return new HeurResult(true, parts[0], null);
            }
            if (p.ExitCode != 0 && !string.IsNullOrWhiteSpace(stderr))
                return new HeurResult(false, null, $"yara rc={p.ExitCode}: {stderr.Trim()}");
            return new HeurResult(false, null, null);
        }
        catch (Exception ex)
        {
            return new HeurResult(false, null, ex.Message);
        }
        finally { Slots.Release(); }
    }
}
