using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Win32;

namespace Malward.NetworkScanner;

public sealed class SystemDnsManager : IDisposable
{
    private static readonly string DataDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data");

    private static readonly string SnapshotPath = Path.Combine(DataDir, "dns-snapshot.json");

    private static readonly string ShieldSettingsPath = Path.Combine(DataDir, "shield-settings.json");

    private sealed record IfaceSnapshot(
        string? Id,
        string Alias,
        string[] DnsIpv4,
        string[] DnsIpv6,
        bool Dhcp);

    private Timer? _watchdog;
    private volatile bool _watchActive;
    private static readonly TimeSpan WatchInterval = TimeSpan.FromSeconds(1);

    public Func<bool>? ProxyAlive { get; set; }

    public Func<bool>? ShieldEnabled { get; set; }

    private int _deadCycles;

    private const int DeadCyclesBeforeRollback = 5;

    private readonly SemaphoreSlim _gate = new(1, 1);

    private volatile bool _stopped;

    private static readonly TimeSpan FlagCacheTtl = TimeSpan.FromSeconds(2);
    private readonly object _flagLock = new();
    private bool _flagCached = true;
    private long _flagReadAtTicks = long.MinValue;

    private bool ReadShieldFlagFromFile()
    {
        lock (_flagLock)
        {
            long now = Stopwatch.GetTimestamp();
            if (_flagReadAtTicks != long.MinValue
                && Stopwatch.GetElapsedTime(_flagReadAtTicks, now) < FlagCacheTtl)
                return _flagCached;

            bool value = true;
            try
            {
                if (File.Exists(ShieldSettingsPath))
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(ShieldSettingsPath));
                    if (doc.RootElement.ValueKind == JsonValueKind.Object
                        && doc.RootElement.TryGetProperty("network_shield_enabled", out var el))
                    {
                        if (el.ValueKind == JsonValueKind.False) value = false;
                        else if (el.ValueKind == JsonValueKind.True) value = true;
                    }
                }
            }
            catch { value = true; }

            _flagCached = value;
            _flagReadAtTicks = now;
            return value;
        }
    }

    private bool IsShieldEnabled()
    {
        bool hook = true;
        var h = ShieldEnabled;
        if (h != null)
        {
            try { hook = h(); } catch { hook = true; }
        }
        return hook && ReadShieldFlagFromFile();
    }

    public async Task ApplyAsync(CancellationToken ct = default)
    {
        if (_stopped)
        {
            Log.Info("DnsMgr", "Apply skipped — system DNS has already been restored on this instance (shield stopping).");
            return;
        }
        if (!IsShieldEnabled())
        {
            Log.Info("DnsMgr", "Apply skipped — the network shield is disabled.");
            return;
        }

        bool acquired = false;
        try
        {
            acquired = await _gate.WaitAsync(TimeSpan.FromSeconds(60), ct);
            if (!acquired)
            {
                Log.Warn("DnsMgr", "Apply skipped — another DNS operation is still running.");
                return;
            }
            if (await MustStandDownAsync("apply")) return;

            var snap = LoadSnapshot();
            if (snap == null)
            {
                snap = ReadCurrentInterfaces();
                SaveSnapshot(snap);
                Log.Info("DnsMgr", $"DNS snapshot saved ({snap.Count} interfaces).");
            }
            else
            {
                int refreshed = RefreshStaleSnapshotEntries(snap);
                Log.Info("DnsMgr", $"DNS snapshot already exists ({snap.Count} interfaces) — keeping it, {refreshed} entries refreshed from current settings.");
            }

            int changed = 0;
            foreach (var nif in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (!IsUserInterface(nif)) continue;
                if (await MustStandDownAsync("apply")) return;

                EnsureInSnapshot(snap, nif);

                var ok = await RunPsAsync(SetLoopbackCommand(nif.Name), ct);
                if (ok) { changed++; Log.Info("DnsMgr", $"DNS {nif.Name} -> 127.0.0.1"); }
                else    { Log.Warn("DnsMgr", $"Failed to set DNS on {nif.Name}"); }

                if (_stopped)
                {
                    Log.Info("DnsMgr", "Apply aborted — a restore was requested while applying.");
                    return;
                }
            }
            Log.Info("DnsMgr", $"Applied 127.0.0.1 on {changed} interfaces.");

            if (await MustStandDownAsync("apply")) return;
            StartWatchdog();
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            Log.Error("DnsMgr", $"Apply DNS failed: {ex.Message}");
        }
        finally
        {
            if (acquired) _gate.Release();
        }
    }

    private async Task<bool> MustStandDownAsync(string phase)
    {
        if (_stopped) return true;
        if (IsShieldEnabled()) return false;

        Log.Info("DnsMgr", $"Network shield disabled during {phase} — restoring system DNS and standing down.");
        _stopped = true;
        StopWatchdog();
        await RestoreCoreAsync(CancellationToken.None);
        return true;
    }

    private void StartWatchdog()
    {
        if (_watchActive || _stopped) return;
        _watchActive = true;
        _watchdog = new Timer(_ => WatchdogTick(), state: null,
            dueTime: WatchInterval, period: WatchInterval);
        Log.Info("DnsMgr", "DNS watchdog active (checking every 1 s).");
    }

    private void StopWatchdog()
    {
        _watchActive = false;
        try { _watchdog?.Dispose(); } catch { }
        _watchdog = null;
    }

    private void WatchdogTick()
    {
        if (!_watchActive || _stopped) return;
        if (!_gate.Wait(0)) return;
        _ = Task.Run(async () =>
        {
            try { await WatchdogTickCoreAsync(); }
            catch (Exception ex) { Log.Debug("DnsMgr", $"watchdog tick error: {ex.Message}"); }
            finally { _gate.Release(); }
        });
    }

    private async Task WatchdogTickCoreAsync()
    {
        if (!_watchActive || _stopped) return;

        if (await MustStandDownAsync("watchdog")) return;

        var alive = ProxyAlive;
        if (alive != null)
        {
            bool ok;
            try { ok = alive(); } catch { ok = true; }
            if (!ok)
            {
                if (++_deadCycles >= DeadCyclesBeforeRollback)
                {
                    Log.Error("DnsMgr", "Resolver on 127.0.0.1 stopped responding — "
                                      + "restoring system DNS settings so the network is not cut off.");
                    _stopped = true;
                    StopWatchdog();
                    await RestoreCoreAsync(CancellationToken.None);
                }

                return;
            }
            _deadCycles = 0;
        }

        var snap = LoadSnapshot() ?? new List<IfaceSnapshot>();
        foreach (var nif in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!_watchActive || _stopped) return;
            if (!IsUserInterface(nif)) continue;
            if (HasOnlyLoopbackDns(nif)) continue;

            if (await MustStandDownAsync("watchdog")) return;

            EnsureInSnapshot(snap, nif);

            Log.Warn("DnsMgr", $"DNS on {nif.Name} is not 127.0.0.1 — re-applying.");
            await RunPsAsync(SetLoopbackCommand(nif.Name), CancellationToken.None);
        }
    }

    private static bool HasOnlyLoopbackDns(NetworkInterface nif)
    {
        try
        {
            var props = nif.GetIPProperties();
            int n = 0;
            bool allLoopback = true;
            foreach (var addr in props.DnsAddresses)
            {
                if (addr.AddressFamily != AddressFamily.InterNetwork) continue;
                n++;
                if (!IPAddress.IsLoopback(addr)) { allLoopback = false; break; }
            }

            return n > 0 && allLoopback;
        }
        catch { return true; }
    }

    private static bool HasStaticLoopbackNameServer(string? ifaceId)
    {
        if (string.IsNullOrEmpty(ifaceId)) return false;
        var v4 = ReadStaticNameServers(TcpipInterfacesKey, ifaceId);
        return v4.Length > 0 && v4.All(IsLoopbackLiteral);
    }

    public static bool HasPendingSnapshot() => File.Exists(SnapshotPath);

    public async Task RecoverStaleAsync(CancellationToken ct = default)
    {
        bool acquired = false;
        try
        {
            if (!HasPendingSnapshot()) return;
            acquired = await _gate.WaitAsync(TimeSpan.FromSeconds(60), ct);
            if (!acquired) { Log.Warn("DnsMgr", "DNS self-repair skipped — another DNS operation is running."); return; }
            if (!HasPendingSnapshot()) return;

            var snap = LoadSnapshot() ?? new List<IfaceSnapshot>();
            bool anyoneOnLoopback =
                snap.Any(s => HasStaticLoopbackNameServer(s.Id))
                || NetworkInterface.GetAllNetworkInterfaces()
                    .Any(n => IsUserInterface(n) && HasStaticLoopbackNameServer(n.Id));
            if (!anyoneOnLoopback)
            {
                try { File.Delete(SnapshotPath); } catch { }
                Log.Info("DnsMgr", "Orphaned DNS snapshot deleted (system settings are correct).");
                return;
            }
            Log.Warn("DnsMgr", "DNS was left on 127.0.0.1 by the previous run — restoring system settings.");
            await RestoreCoreAsync(ct);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { Log.Error("DnsMgr", $"DNS self-repair failed: {ex.Message}"); }
        finally
        {
            if (acquired) _gate.Release();
        }
    }

    public async Task<int> RepairOrphanedLoopbackAsync(CancellationToken ct = default)
    {
        int fixedCount = 0;
        bool acquired = false;
        try
        {
            acquired = await _gate.WaitAsync(TimeSpan.FromSeconds(60), ct);
            if (!acquired) { Log.Warn("DnsMgr", "Orphaned-loopback repair skipped — another DNS operation is running."); return 0; }

            foreach (var nif in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (!IsUserInterface(nif)) continue;
                var v4 = ReadStaticNameServers(TcpipInterfacesKey, nif.Id);
                if (v4.Length == 0 || !v4.All(IsLoopbackLiteral)) continue;

                if (IsLoopbackResolverListening())
                {
                    Log.Info("DnsMgr", $"{nif.Name} points at 127.0.0.1 and a resolver is listening there — leaving it alone.");
                    continue;
                }
                Log.Warn("DnsMgr", $"{nif.Name} has static DNS 127.0.0.1 but nothing listens on 127.0.0.1:53 — resetting to automatic (DHCP).");
                var ok = await RunPsAsync(ResetCommand(nif.Name), ct);
                if (ok) { fixedCount++; Log.Info("DnsMgr", $"DNS {nif.Name} -> automatic (DHCP)"); }
                else    { Log.Warn("DnsMgr", $"Failed to reset DNS on {nif.Name}"); }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { Log.Error("DnsMgr", $"Orphaned-loopback repair failed: {ex.Message}"); }
        finally
        {
            if (acquired) _gate.Release();
        }
        return fixedCount;
    }

    private static bool IsLoopbackResolverListening()
    {
        try
        {
            var listeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners();
            foreach (var ep in listeners)
            {
                if (ep.Port != 53) continue;
                if (IPAddress.IsLoopback(ep.Address)
                    || ep.Address.Equals(IPAddress.Any)
                    || ep.Address.Equals(IPAddress.IPv6Any))
                    return true;
            }
        }
        catch
        {
            return ExclusiveBindProbeSaysListening();
        }
        return false;
    }

    private static bool ExclusiveBindProbeSaysListening()
    {
        try
        {
            using var probe = new UdpClient(AddressFamily.InterNetwork);
            probe.Client.ExclusiveAddressUse = true;
            probe.Client.Bind(new IPEndPoint(IPAddress.Loopback, 53));
            return false;
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AddressAlreadyInUse
                                         || ex.SocketErrorCode == SocketError.AccessDenied)
        {
            return true;
        }
        catch
        {
            return true;
        }
    }

    public async Task RestoreAsync(CancellationToken ct = default)
    {
        _stopped = true;
        StopWatchdog();

        bool acquired = false;
        try
        {
            acquired = await _gate.WaitAsync(TimeSpan.FromSeconds(120), ct);
            if (!acquired)
            {
                Log.Error("DnsMgr", "Restore could not acquire the DNS gate within 120 s — snapshot kept for the next attempt.");
                return;
            }
            await RestoreCoreAsync(ct);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            Log.Error("DnsMgr", $"Restore DNS failed: {ex.Message}");
        }
        finally
        {
            if (acquired) _gate.Release();
        }
    }

    private async Task RestoreCoreAsync(CancellationToken ct)
    {
        try
        {
            var snap = LoadSnapshot();
            if (snap == null)
            {
                Log.Info("DnsMgr", "No DNS snapshot — nothing to restore.");
                return;
            }

            var byId = new Dictionary<string, NetworkInterface>(StringComparer.OrdinalIgnoreCase);
            var byAlias = new Dictionary<string, NetworkInterface>(StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (var n in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (!string.IsNullOrEmpty(n.Id)) byId[n.Id] = n;
                    if (!string.IsNullOrEmpty(n.Name)) byAlias[n.Name] = n;
                }
            }
            catch { }

            int failed = 0, restored = 0, skipped = 0, absent = 0;
            foreach (var s in snap)
            {
                string alias = s.Alias;
                NetworkInterface? cur = null;
                if (!string.IsNullOrEmpty(s.Id)) byId.TryGetValue(s.Id, out cur);
                if (cur == null && !string.IsNullOrEmpty(s.Alias)) byAlias.TryGetValue(s.Alias, out cur);
                if (cur != null && !string.IsNullOrEmpty(cur.Name)) alias = cur.Name;

                if (cur == null)
                {
                    absent++;
                    Log.Warn("DnsMgr", $"{alias} is not present on this machine any more — skipping it (not counted as a failure).");
                    continue;
                }

                if (!string.IsNullOrEmpty(s.Id) && !HasStaticLoopbackNameServer(s.Id))
                {
                    skipped++;
                    Log.Info("DnsMgr", $"{alias} is not on 127.0.0.1 any more — leaving it as is.");
                    continue;
                }

                var v4 = (s.DnsIpv4 ?? Array.Empty<string>()).Where(a => !IsLoopbackLiteral(a)).ToArray();
                var v6 = (s.DnsIpv6 ?? Array.Empty<string>()).Where(a => !IsLoopbackLiteral(a)).ToArray();

                bool ok;
                string how;
                if (s.Dhcp || v4.Length == 0)
                {
                    ok = await RunPsAsync(ResetCommand(alias), ct);
                    how = "automatic (DHCP)";
                    if (ok && v6.Length > 0)
                    {
                        ok = await RunPsAsync(SetCommand(alias, v6), ct);
                        how += " + IPv6 " + string.Join(",", v6);
                    }
                }
                else
                {
                    var all = v4.Concat(v6).ToArray();
                    ok = await RunPsAsync(SetCommand(alias, all), ct);
                    how = string.Join(",", all);
                }

                if (ok) { restored++; Log.Info("DnsMgr", $"DNS {alias} -> {how}"); }
                else    { failed++;   Log.Warn("DnsMgr", $"Failed to restore DNS on {alias} (wanted: {how})"); }
            }

            if (failed == 0)
            {
                try { File.Delete(SnapshotPath); } catch { }
                Log.Info("DnsMgr", $"DNS snapshot restored ({restored} restored, {skipped} left as is, {absent} absent) and deleted.");
            }
            else
            {
                Log.Warn("DnsMgr", $"DNS restore incomplete: {restored} restored, {failed} failed, {skipped} left as is, {absent} absent — snapshot kept for the next attempt.");
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            Log.Error("DnsMgr", $"Restore DNS failed: {ex.Message}");
        }
    }

    private const string TcpipInterfacesKey  = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
    private const string Tcpip6InterfacesKey = @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces";

    private static List<IfaceSnapshot>? LoadSnapshot()
    {
        try
        {
            if (!File.Exists(SnapshotPath)) return null;
            var json = File.ReadAllText(SnapshotPath);
            var arr = JsonSerializer.Deserialize<IfaceSnapshot[]>(json) ?? Array.Empty<IfaceSnapshot>();
            return arr.ToList();
        }
        catch (Exception ex)
        {
            Log.Warn("DnsMgr", $"DNS snapshot unreadable: {ex.Message}");
            return null;
        }
    }

    private static void SaveSnapshot(List<IfaceSnapshot> snap)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(SnapshotPath)!);
        File.WriteAllText(SnapshotPath, JsonSerializer.Serialize(snap.ToArray(),
            new JsonSerializerOptions { WriteIndented = true }));
    }

    private static void EnsureInSnapshot(List<IfaceSnapshot> snap, NetworkInterface nif)
    {
        try
        {
            bool known = snap.Any(s =>
                (!string.IsNullOrEmpty(s.Id) && string.Equals(s.Id, nif.Id, StringComparison.OrdinalIgnoreCase))
                || (string.IsNullOrEmpty(s.Id) && string.Equals(s.Alias, nif.Name, StringComparison.OrdinalIgnoreCase)));
            if (known) return;
            var entry = ReadInterfaceSnapshot(nif);
            snap.Add(entry);
            SaveSnapshot(snap);
            Log.Info("DnsMgr", $"Interface {nif.Name} added to the DNS snapshot ({DescribeEntry(entry)}).");
        }
        catch (Exception ex)
        {
            Log.Warn("DnsMgr", $"Could not record {nif.Name} in the DNS snapshot: {ex.Message}");
        }
    }

    private static int RefreshStaleSnapshotEntries(List<IfaceSnapshot> snap)
    {
        int refreshed = 0;
        bool dirty = false;
        try
        {
            foreach (var nif in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (!IsUserInterface(nif) || string.IsNullOrEmpty(nif.Id)) continue;
                int idx = snap.FindIndex(s => !string.IsNullOrEmpty(s.Id)
                    && string.Equals(s.Id, nif.Id, StringComparison.OrdinalIgnoreCase));
                if (idx < 0) continue;
                if (HasStaticLoopbackNameServer(nif.Id)) continue;

                var fresh = ReadInterfaceSnapshot(nif);
                var old = snap[idx];

                var oldV4 = old.DnsIpv4 ?? Array.Empty<string>();
                var oldV6 = old.DnsIpv6 ?? Array.Empty<string>();
                bool sameDns = old.Dhcp == fresh.Dhcp
                    && oldV4.SequenceEqual(fresh.DnsIpv4, StringComparer.OrdinalIgnoreCase)
                    && oldV6.SequenceEqual(fresh.DnsIpv6, StringComparer.OrdinalIgnoreCase);
                bool sameAlias = string.Equals(old.Alias, fresh.Alias, StringComparison.OrdinalIgnoreCase);
                if (sameDns && sameAlias) continue;

                snap[idx] = fresh;
                dirty = true;
                if (sameDns) continue;
                refreshed++;
                Log.Info("DnsMgr", $"Snapshot entry for {nif.Name} refreshed: {DescribeEntry(old)} -> {DescribeEntry(fresh)}.");
            }
            if (dirty) SaveSnapshot(snap);
        }
        catch (Exception ex)
        {
            Log.Warn("DnsMgr", $"Could not refresh the DNS snapshot from current settings: {ex.Message}");
        }
        return refreshed;
    }

    private static string DescribeEntry(IfaceSnapshot s)
    {
        var v4 = s.DnsIpv4 ?? Array.Empty<string>();
        var v6 = s.DnsIpv6 ?? Array.Empty<string>();
        return s.Dhcp && v6.Length == 0 ? "automatic"
            : string.Join(",", v4.Concat(v6)) + (s.Dhcp ? " (IPv4 automatic)" : "");
    }

    private static List<IfaceSnapshot> ReadCurrentInterfaces()
    {
        var list = new List<IfaceSnapshot>();
        foreach (var nif in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!IsUserInterface(nif)) continue;
            try { list.Add(ReadInterfaceSnapshot(nif)); }
            catch (Exception ex) { Log.Warn("DnsMgr", $"Could not read DNS settings of {nif.Name}: {ex.Message}"); }
        }
        return list;
    }

    private static IfaceSnapshot ReadInterfaceSnapshot(NetworkInterface nif)
    {
        var v4 = ReadStaticNameServers(TcpipInterfacesKey, nif.Id);
        var v6 = ReadStaticNameServers(Tcpip6InterfacesKey, nif.Id);

        bool dhcp = v4.Length == 0;
        if (v4.Length > 0 && v4.All(IsLoopbackLiteral))
        {
            Log.Warn("DnsMgr", $"{nif.Name} already has static DNS {string.Join(",", v4)} (leftover of a previous run) — recording it as automatic.");
            v4 = Array.Empty<string>();
            dhcp = true;
        }
        if (v6.Length > 0 && v6.All(IsLoopbackLiteral))
        {
            Log.Warn("DnsMgr", $"{nif.Name} has static IPv6 DNS {string.Join(",", v6)} (loopback) — recording it as automatic.");
            v6 = Array.Empty<string>();
        }
        return new IfaceSnapshot(nif.Id, nif.Name, v4, v6, dhcp);
    }

    private static string[] ReadStaticNameServers(string interfacesKey, string ifaceId)
    {
        try
        {
            if (string.IsNullOrEmpty(ifaceId)) return Array.Empty<string>();
            using var key = Registry.LocalMachine.OpenSubKey(interfacesKey + "\\" + ifaceId, writable: false);
            var raw = key?.GetValue("NameServer") as string;
            if (string.IsNullOrWhiteSpace(raw)) return Array.Empty<string>();
            return raw.Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                      .Where(a => IPAddress.TryParse(a, out _))
                      .ToArray();
        }
        catch { return Array.Empty<string>(); }
    }

    private static bool IsLoopbackLiteral(string s) =>
        IPAddress.TryParse(s?.Trim(), out var ip) && IPAddress.IsLoopback(ip);

    private static bool IsUserInterface(NetworkInterface nif)
    {
        if (nif.OperationalStatus != OperationalStatus.Up) return false;
        if (nif.NetworkInterfaceType == NetworkInterfaceType.Loopback) return false;
        if (nif.NetworkInterfaceType == NetworkInterfaceType.Tunnel) return false;

        var desc = (nif.Description ?? "") + " " + (nif.Name ?? "");
        if (desc.Contains("vEthernet", StringComparison.OrdinalIgnoreCase)) return false;
        if (desc.Contains("WSL", StringComparison.OrdinalIgnoreCase)) return false;
        if (desc.Contains("VMware", StringComparison.OrdinalIgnoreCase)) return false;
        if (desc.Contains("VirtualBox", StringComparison.OrdinalIgnoreCase)) return false;
        return true;
    }

    private static string Escape(string s) => s.Replace("'", "''");

    private static string SetLoopbackCommand(string alias) =>
        $"Set-DnsClientServerAddress -InterfaceAlias '{Escape(alias)}' -ServerAddresses ('127.0.0.1')";

    private static string ResetCommand(string alias) =>
        $"Set-DnsClientServerAddress -InterfaceAlias '{Escape(alias)}' -ResetServerAddresses";

    private static string SetCommand(string alias, string[] addrs) =>
        $"Set-DnsClientServerAddress -InterfaceAlias '{Escape(alias)}' -ServerAddresses ({string.Join(",", addrs.Select(a => $"'{Escape(a)}'"))})";

    public void Dispose()
    {
        _stopped = true;
        StopWatchdog();
    }

    private static async Task<bool> RunPsAsync(string command, CancellationToken ct)
    {
        try
        {
            var psi = new ProcessStartInfo("powershell.exe")
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            psi.ArgumentList.Add("-NoProfile");
            psi.ArgumentList.Add("-NonInteractive");
            psi.ArgumentList.Add("-ExecutionPolicy");
            psi.ArgumentList.Add("Bypass");
            psi.ArgumentList.Add("-Command");
            psi.ArgumentList.Add(command);

            using var p = Process.Start(psi);
            if (p == null) return false;
            await p.WaitForExitAsync(ct);
            return p.ExitCode == 0;
        }
        catch { return false; }
    }
}
