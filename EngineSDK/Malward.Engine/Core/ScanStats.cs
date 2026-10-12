using System.Globalization;
using System.Text;

namespace Malward.Engine.Core;

public sealed class ScanStats
{
    public long Encrypted;
    public long Blocked;
    public long Safe;
    public long Cloud;
    public long Threats;
    public long Skipped;
    public long System;
    public long BytesScanned;
    public long FilesTotal;

    private readonly DateTime _startUtc = DateTime.UtcNow;

    public void RecordResult(DetectionResult r)
    {
        Interlocked.Increment(ref FilesTotal);
        if (r.FileSize > 0) Interlocked.Add(ref BytesScanned, r.FileSize);

        if (r.Source != null && r.Source.StartsWith("System:", StringComparison.Ordinal))
        {
            Interlocked.Increment(ref System);
            Interlocked.Increment(ref Safe);
            return;
        }

        if (r.Source != null && r.Source.StartsWith("Cloud:", StringComparison.Ordinal))
            Interlocked.Increment(ref Cloud);

        switch (r.Verdict)
        {
            case Verdict.Malware:
                Interlocked.Increment(ref Threats);
                break;
            case Verdict.Clean:
                Interlocked.Increment(ref Safe);
                break;
            case Verdict.Skipped:
                Interlocked.Increment(ref Skipped);
                if (r.Error != null)
                {
                    if (r.Error.Contains("password", StringComparison.OrdinalIgnoreCase)
                     || r.Error.Contains("encrypt", StringComparison.OrdinalIgnoreCase))
                        Interlocked.Increment(ref Encrypted);

                    else if (r.Error.Contains("Access", StringComparison.OrdinalIgnoreCase)
                          || r.Error.Contains("denied", StringComparison.OrdinalIgnoreCase)
                          || r.Error.Contains("blocked", StringComparison.OrdinalIgnoreCase)
                          || r.Error.Contains("locked", StringComparison.OrdinalIgnoreCase))
                        Interlocked.Increment(ref Blocked);
                }
                break;
            case Verdict.Error:
                if (r.Error != null && (r.Error.Contains("Access", StringComparison.OrdinalIgnoreCase)
                                     || r.Error.Contains("denied", StringComparison.OrdinalIgnoreCase)
                                     || r.Error.Contains("blocked", StringComparison.OrdinalIgnoreCase)))
                    Interlocked.Increment(ref Blocked);
                break;
        }
    }

    public void RecordThreatOnly() => Interlocked.Increment(ref Threats);

    public void RecordBlocked()
    {
        Interlocked.Increment(ref FilesTotal);
        Interlocked.Increment(ref Blocked);
    }

    public TimeSpan Elapsed => DateTime.UtcNow - _startUtc;

    private static string FormatBytes(long b)
    {
        if (b < 1024) return $"{b} B";
        if (b < 1024L * 1024) return $"{b / 1024.0:F1} KB";
        if (b < 1024L * 1024 * 1024) return $"{b / 1024.0 / 1024:F1} MB";
        return $"{b / 1024.0 / 1024 / 1024:F2} GB";
    }

    private static string FormatTime(TimeSpan t)
    {
        if (t.TotalHours >= 1) return $"{(int)t.TotalHours}h {t.Minutes:D2}m {t.Seconds:D2}s";
        if (t.TotalMinutes >= 1) return $"{t.Minutes}m {t.Seconds:D2}s";
        return $"{t.TotalSeconds:F1}s";
    }

    public string BuildReport(string? scanTarget = null, IReadOnlyList<string>? folders = null)
    {
        var sb = new StringBuilder();
        sb.AppendLine("============================================================");
        sb.AppendLine("  Malward — raport skanowania");
        if (folders is { Count: > 1 })
        {
            sb.AppendLine($"  Przeskanowane foldery ({folders.Count}):");
            foreach (var f in folders) sb.AppendLine($"    • {f}");
        }
        else if (!string.IsNullOrEmpty(scanTarget))
            sb.AppendLine($"  Cel: {scanTarget}");
        sb.AppendLine($"  Zakończono: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine("------------------------------------------------------------");
        sb.AppendLine($"  Pliki zaszyfrowane:              {Volatile.Read(ref Encrypted),10}");
        sb.AppendLine($"  Pliki zablokowane:               {Volatile.Read(ref Blocked),10}");
        sb.AppendLine($"  Plików bezpiecznych:             {Volatile.Read(ref Safe),10}");
        sb.AppendLine($"  Plików sprawdzonych w chmurze:   {Volatile.Read(ref Cloud),10}");
        sb.AppendLine($"  Plików systemowych (pominięto): {Volatile.Read(ref System),10}");

        sb.AppendLine($"  Pliki pominięte:                 {Volatile.Read(ref Skipped),10}");
        sb.AppendLine($"  Zagrożeń:                        {Volatile.Read(ref Threats),10}");
        sb.AppendLine("------------------------------------------------------------");
        sb.AppendLine($"  Czas skanowania:    {FormatTime(Elapsed)}");
        sb.AppendLine($"  Przeskanowanych danych:  {FormatBytes(Volatile.Read(ref BytesScanned))}");
        sb.AppendLine($"  Plików łącznie:     {Volatile.Read(ref FilesTotal):N0}");
        sb.AppendLine("============================================================");
        return sb.ToString();
    }
}
