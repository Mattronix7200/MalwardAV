using System.Diagnostics;

namespace Malward.NetworkScanner;

public sealed class QuicGuard
{
    private const string RuleName = "Malward-Block-QUIC-UDP443";

    private static readonly string MarkerPath =
        Path.Combine(PolicyGuard.DataDir, "quic.blocked");

    public static bool HasPendingMarker() => File.Exists(MarkerPath);

    public void Apply()
    {
        Netsh($"advfirewall firewall delete rule name=\"{RuleName}\"", ignoreError: true);

        var (code, err) = Run($"advfirewall firewall add rule name=\"{RuleName}\" dir=out "
                              + "action=block protocol=UDP remoteport=443 profile=any");
        if (code != 0)
        {
            Log.Warn("Quic", $"Could not block QUIC: {err.Trim()} — Chrome and Edge will keep "
                           + "reaching Google over UDP/443, where the address filter cannot see them.");
            return;
        }

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(MarkerPath)!);
            File.WriteAllText(MarkerPath, DateTime.UtcNow.ToString("O"));
        }
        catch { }

        Log.Info("Quic", "QUIC/HTTP3 on UDP/443 blocked — browsers fall back to TCP, which is the "
                       + "only way the content filter can see requests to Google, YouTube and "
                       + "anything behind Cloudflare.");
    }

    public void Remove()
    {
        Netsh($"advfirewall firewall delete rule name=\"{RuleName}\"", ignoreError: true);
        try { if (File.Exists(MarkerPath)) File.Delete(MarkerPath); } catch { }
        Log.Info("Quic", "QUIC/HTTP3 block removed.");
    }

    private static void Netsh(string args, bool ignoreError = false)
    {
        try
        {
            var (code, err) = Run(args);
            if (code != 0 && !ignoreError && !string.IsNullOrWhiteSpace(err))
                Log.Warn("Quic", $"netsh ({args}) -> {err.Trim()}");
        }
        catch (Exception ex) { Log.Warn("Quic", $"netsh failed: {ex.Message}"); }
    }

    private static (int code, string err) Run(string args)
    {
        var psi = new ProcessStartInfo("netsh", args)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var p = Process.Start(psi)!;
        var errTask = p.StandardError.ReadToEndAsync();
        var outTask = p.StandardOutput.ReadToEndAsync();
        if (!p.WaitForExit(10000))
        {
            try { p.Kill(entireProcessTree: true); } catch { }
            return (-1, "netsh timed out after 10 s");
        }
        var err = errTask.Wait(2000) ? errTask.Result : "";
        _ = outTask.Wait(2000);
        return (p.ExitCode, err);
    }
}
