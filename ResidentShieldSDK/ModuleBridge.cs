namespace Malward.ResidentShield;

/// <summary>Every call into an optional module goes through here.
///
/// The JIT loads an assembly when it compiles a method whose body mentions a type from it, which
/// happens as the method is entered - before any guard inside it can run. A method that touches
/// netmonitor or bkmonitor therefore throws FileNotFoundException on a machine where the user did
/// not install that module, and the shield around it dies with it. Keeping those touches in
/// wrappers whose own signatures mention nothing foreign means the caller compiles cleanly, and
/// the wrapper is only ever entered once the presence check below has passed.</summary>
internal static class ModuleBridge
{
    public static bool NetworkInstalled => Present("netmonitor.dll");

    public static bool BackupInstalled => Present("bkmonitor.dll");

    private static bool Present(string file)
    {
        try { return File.Exists(Path.Combine(AppContext.BaseDirectory, file)); }
        catch { return false; }
    }

    public static string NetworkConfigPath() => Malward.NetworkScanner.NetworkConfig.DefaultPath;

    public static string BackupConfigPath() => Malward.BackupEngine.BackupConfig.DefaultConfigPath;

    public static void BackupBootSector() => Malward.BackupEngine.BootSectorGuard.Backup();

    public static void WireDangerousConnections(Action<int, string, string, string, int, string> onHit)
        => Malward.NetworkScanner.DangerousConnectionBus.Handler =
            c => onHit(c.Pid, c.ProcessName, c.ImagePath, c.RemoteIp, c.RemotePort, c.Detection);

    public static void UnwireDangerousConnections()
        => Malward.NetworkScanner.DangerousConnectionBus.Handler = null;

    public static bool DnsSnapshotPending()
        => Malward.NetworkScanner.SystemDnsManager.HasPendingSnapshot();

    public static bool NetworkPoliciesPending()
        => Malward.NetworkScanner.NetworkPolicies.AnythingApplied();

    public static void ClearNetworkPolicies()
        => Malward.NetworkScanner.NetworkPolicies.ClearAll();

    public static async Task<int> RepairStaleDnsAsync(bool recoverSnapshot)
    {
        Malward.NetworkScanner.Log.FileLoggingEnabled = true;
        var manager = new Malward.NetworkScanner.SystemDnsManager();
        if (recoverSnapshot) await manager.RecoverStaleAsync();
        return await manager.RepairOrphanedLoopbackAsync();
    }

    public static bool BadIpListEmpty() => BadIps.List.IsEmpty;

    public static bool IsBadIp(string ip) => BadIps.List.Contains(ip);

    private static class BadIps
    {
        public static readonly Malward.NetworkScanner.BotIpBlocklist List =
            new(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                             "Malward", "data", "vps-ex01.vdeb"));
    }
}
