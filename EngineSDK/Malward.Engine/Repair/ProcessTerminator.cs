using System.Diagnostics;
using Malward.Engine.Util;

namespace Malward.Engine.Repair;

public static class ProcessTerminator
{
    private const int KillWaitMs = 3000;

    private const int MaxKillAttempts = 2;

    public static int TerminateProcessesUsingFile(string filePath)
    {
        int killed = 0;
        var target = Path.GetFullPath(filePath);

        if (ProcessOwnership.IsSystemPath(target))
        {
            Console.Error.WriteLine($"[!] Skipping terminate for system file: {target}");
            return 0;
        }

        foreach (var p in Process.GetProcesses())
        {
            try
            {
                if (!ProcessOwnership.IsCurrentUserNonCritical(p)) continue;

                var modPath = ProcessOwnership.TryGetImagePath(p);
                if (modPath == null) continue;
                if (!string.Equals(Path.GetFullPath(modPath), target, StringComparison.OrdinalIgnoreCase))
                    continue;

                bool done = false;
                for (int attempt = 1; attempt <= MaxKillAttempts && !done; attempt++)
                {
                    try
                    {
                        if (p.HasExited) { done = true; break; }
                        p.Kill(entireProcessTree: true);

                        p.WaitForExit(KillWaitMs);
                        done = p.HasExited;
                        if (!done && attempt < MaxKillAttempts)
                            Console.Error.WriteLine($"[!] Kill attempt {attempt} — process {p.Id} still alive, retrying…");
                    }
                    catch (InvalidOperationException)
                    {
                        done = true;
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"[!] Kill({p.Id}): {ex.Message}");
                        break;
                    }
                }

                if (done) killed++;
                else Console.Error.WriteLine($"[!] Failed to kill pid={p.Id} using '{target}'");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[!] ProcessTerminator.Enumerate: {ex.Message}");
            }
            finally { p.Dispose(); }
        }
        return killed;
    }
}
