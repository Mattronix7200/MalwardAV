using System.Runtime.InteropServices;
using Malward.Engine.Archive;
using Malward.Engine.Cloud;
using Malward.Engine.Config;
using Malward.Engine.Core;
using Malward.Engine.Quarantine;
using Malward.Engine.Util;

namespace Malward.Engine.Repair;

public sealed record RepairOutcome(string Action, bool Success, string? Detail,
                                   bool RebootRequired = false);

public enum RemovalResult { Removed, ScheduledForReboot, Failed }

public sealed class Repairer
{
    private readonly Settings _settings;
    private readonly QuarantineStore _store;
    private readonly ServerClient? _cloud;
    private readonly ArchiveScanner _archiveScanner = new();

    public Repairer(Settings settings, ServerClient? cloud = null)
    {
        _settings = settings;
        _store = new QuarantineStore
        {
            SizeLimitBytes = settings.QuarantineSizeLimitMb > 0
                ? (long)settings.QuarantineSizeLimitMb * 1024 * 1024
                : long.MaxValue,
        };
        _cloud = cloud;
    }

    public static bool IsHeuristic(DetectionResult r)
        => (r.Source?.StartsWith("Heur", StringComparison.OrdinalIgnoreCase) ?? false)
           || (r.Detection?.StartsWith("Heur.", StringComparison.OrdinalIgnoreCase) ?? false);

    public static bool IsVulnerableDriver(DetectionResult r)
        => string.Equals(r.Source, Core.ScanPipeline.ByodSource, StringComparison.Ordinal);

    public static bool IsUnverified(DetectionResult r)
        => string.Equals(r.Source, Core.ScanPipeline.UnverifiedSource, StringComparison.Ordinal);

    public RepairOutcome Repair(DetectionResult r, bool userInitiated = false)
    {
        if (r.Verdict != Verdict.Malware) return new RepairOutcome("noop", true, "not malware");

        bool systemPath = false;
        try
        {
            systemPath = SystemFileCheck.IsSystemFile(r.Path);
            if (systemPath && !IsVulnerableDriver(r) && SystemFileCheck.IsGenuineSystemFile(r.Path))
            {
                if (_cloud != null && !string.IsNullOrEmpty(r.Sha256))
                    _ = Task.Run(() => _cloud.SubmitCleanAsync(r.Sha256));
                return new RepairOutcome("system-skip", true,
                    "genuine system file → auto-whitelist");
            }
        }
        catch {  }

        if (!userInitiated && IsHeuristic(r))
            return new RepairOutcome("deferred", true, "heur-ask");

        if (!userInitiated && IsUnverified(r))
            return new RepairOutcome("deferred", true, "unverified-ask");

        if (!string.IsNullOrEmpty(r.ArchiveEntry))
            return RepairArchive(r);

        if (_settings.RepairMode == 0)
            return new RepairOutcome("deferred", true, "user-ask");

        int killed = ProcessTerminator.TerminateProcessesUsingFile(r.Path);

        RepairOutcome outcome;
        switch (_settings.RepairMode)
        {
            case 3: outcome = TryDelete(r); break;
            case 2: outcome = TryQuarantine(r); break;
            case 1:
            default:
            {
                var q = TryQuarantine(r);
                if (q.Success) { outcome = q with { Detail = $"killed={killed}; {q.Detail}" }; break; }
                var d = TryDelete(r);
                if (d.Success) { outcome = d with { Detail = $"killed={killed}; quarantine_failed→deleted" }; break; }
                outcome = new RepairOutcome("ignore", false,
                    $"killed={killed}; quarantine_err={q.Detail}; delete_err={d.Detail}");
                break;
            }
        }

        if (systemPath && outcome.Success && outcome.Action is "quarantine" or "delete")
            outcome = SystemFileRestore.AfterRemoval(r.Path, outcome);
        return outcome;
    }

    private RepairOutcome RepairArchive(DetectionResult r)
    {
        if (_settings.RepairMode == 0)
            return new RepairOutcome("deferred", true, "user-ask");

        if (_settings.ArchiveRepairMode == 1)
        {
            ProcessTerminator.TerminateProcessesUsingFile(r.Path);
            return TryDelete(r);
        }

        var entries = (r.ArchiveEntry ?? "")
            .Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToList();

        if (entries.Count == 0) return TryDelete(r);
        try
        {
            int removed = 0;
            var failed = new List<string>();
            foreach (var chain in entries)
            {
                var parts = chain.Split(Archive.ArchiveScanner.ChainSep,
                    StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                if (_archiveScanner.RemoveEntryChain(r.Path, parts)) removed++;
                else failed.Add(chain);
            }

            if (failed.Count == 0)
                return new RepairOutcome("archive-entry-removed", true,
                    $"usunięto {removed} wpis(ów) z {Path.GetFileName(r.Path)}");

            return new RepairOutcome("archive-entry-removed", false,
                $"usunięto {removed}, nie udało się {failed.Count} " +
                $"({string.Join(", ", failed.Take(3))}) — archiwum pozostaje");
        }
        catch (Exception ex)
        {
            return new RepairOutcome("archive-entry-removed", false, ex.Message);
        }
    }

    private RepairOutcome TryQuarantine(DetectionResult r)
    {
        try
        {
            try { ProcessTerminator.TerminateProcessesUsingFile(r.Path); } catch { }

            var id = _store.Add(r.Path, r.Detection ?? "unknown", r.Sha256);

            try { File.Delete(r.Path); }
            catch (Exception delEx)
            {
                try { ProcessTerminator.TerminateProcessesUsingFile(r.Path); } catch { }
                switch (ForceRemove(r.Path))
                {
                    case RemovalResult.Removed:
                        return new RepairOutcome("quarantine", true,
                            $"id={id}; forced-delete ({delEx.GetType().Name})");

                    case RemovalResult.ScheduledForReboot:
                        return new RepairOutcome("quarantine-reboot", false,
                            $"id={id}; the original is locked and still readable, "
                            + "its removal is scheduled for the next restart",
                            RebootRequired: true);

                    default:
                        try { _store.Delete(id); } catch { }
                        return new RepairOutcome("quarantine", false,
                            "the original could not be removed (locked or in use) and no removal was scheduled");
                }
            }
            return new RepairOutcome("quarantine", true, $"id={id}");
        }
        catch (Exception ex)
        {
            return new RepairOutcome("quarantine", false, ex.Message);
        }
    }

    private RepairOutcome TryDelete(DetectionResult r)
    {
        if (!File.Exists(r.Path))
            return new RepairOutcome("delete", true, "already gone");
        try
        {
            try { ProcessTerminator.TerminateProcessesUsingFile(r.Path); } catch { }
            SecureFileEraser.Shred(r.Path);

            if (File.Exists(r.Path))
                return new RepairOutcome("delete", false, "shred completed but file remains");
            return new RepairOutcome("delete", true, "secure-shred");
        }
        catch (Exception ex)
        {
            try { ProcessTerminator.TerminateProcessesUsingFile(r.Path); } catch { }
            return ForceRemove(r.Path) switch
            {
                RemovalResult.Removed => new RepairOutcome("delete", true,
                    $"forced-delete ({ex.GetType().Name})"),

                RemovalResult.ScheduledForReboot => new RepairOutcome("delete-reboot", false,
                    "the file is locked and still readable, "
                    + "its removal is scheduled for the next restart", RebootRequired: true),

                _ => new RepairOutcome("delete", false,
                    "access denied or the file is in use despite elevation"),
            };
        }
    }

    private const int MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool MoveFileEx(string lpExistingFileName, string? lpNewFileName, int dwFlags);

    private static RemovalResult ForceRemove(string path)
    {
        try
        {
            try { ProcessTerminator.TerminateProcessesUsingFile(path); } catch { }
            try { File.SetAttributes(path, FileAttributes.Normal); } catch { }
            RunTool("takeown.exe", $"/f \"{path}\"");

            RunTool("icacls.exe", $"\"{path}\" /grant *S-1-5-32-544:F /C /Q");
            try { File.SetAttributes(path, FileAttributes.Normal); } catch { }

            try { SecureFileEraser.Shred(path); } catch { try { File.Delete(path); } catch { } }
            if (!File.Exists(path)) return RemovalResult.Removed;
        }
        catch { }

        try
        {
            return MoveFileEx(path, null, MOVEFILE_DELAY_UNTIL_REBOOT)
                ? RemovalResult.ScheduledForReboot
                : RemovalResult.Failed;
        }
        catch { return RemovalResult.Failed; }
    }

    private static void RunTool(string exe, string args)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo(exe, args)
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            using var p = System.Diagnostics.Process.Start(psi);
            p?.WaitForExit(5000);
        }
        catch { }
    }
}
