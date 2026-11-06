using System.Diagnostics;
using System.Net;

namespace Malward.NetworkScanner;

public sealed class DnsLeakGuard
{
    private const string BlockUdpRule = "Malward — obcy serwer DNS (UDP)";
    private const string BlockTcpRule = "Malward — obcy serwer DNS (TCP)";

    private static readonly (uint First, uint Last) Loopback =
        (ToNumber("127.0.0.0"), ToNumber("127.255.255.255"));

    private static readonly string MarkerPath = Path.Combine(PolicyGuard.DataDir, "dnsleak.applied");

    public static bool RulesApplied() => File.Exists(MarkerPath);

    public static uint ToNumber(string address)
    {
        var bytes = IPAddress.Parse(address).GetAddressBytes();
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }

    public static string ToAddress(uint value) =>
        $"{(value >> 24) & 0xFF}.{(value >> 16) & 0xFF}.{(value >> 8) & 0xFF}.{value & 0xFF}";

    public static string RemoteRangesExcept(string? upstream)
    {
        var holes = new List<(uint First, uint Last)> { Loopback };
        if (!string.IsNullOrWhiteSpace(upstream)
            && IPAddress.TryParse(upstream, out var parsed)
            && parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            uint one = ToNumber(parsed.ToString());
            holes.Add((one, one));
        }

        holes.Sort((a, b) => a.First.CompareTo(b.First));

        var ranges = new List<string>();
        uint cursor = 0;
        foreach (var (first, last) in holes)
        {
            if (first > cursor) ranges.Add($"{ToAddress(cursor)}-{ToAddress(first - 1)}");
            if (last == uint.MaxValue) return string.Join(",", ranges);
            cursor = Math.Max(cursor, last + 1);
        }
        ranges.Add($"{ToAddress(cursor)}-{ToAddress(uint.MaxValue)}");
        return string.Join(",", ranges);
    }

    public void Apply(string? upstream)
    {
        string ranges = RemoteRangesExcept(upstream);
        Remove();

        bool udp = AddRule(BlockUdpRule, "UDP", ranges);
        bool tcp = AddRule(BlockTcpRule, "TCP", ranges);

        if (udp || tcp)
        {
            try
            {
                Directory.CreateDirectory(PolicyGuard.DataDir);
                File.WriteAllText(MarkerPath, upstream ?? "");
            }
            catch { }
            Log.Info("DnsLeak", $"Outbound DNS to any resolver other than {upstream ?? "the configured one"} "
                                + "is now blocked, so a program with its own server cannot slip past the filter.");
        }
        else
            Log.Warn("DnsLeak", "Could not add the firewall rules blocking foreign DNS servers.");
    }

    public void Remove()
    {
        foreach (var name in new[] { BlockUdpRule, BlockTcpRule })
            Netsh($"advfirewall firewall delete rule name=\"{name}\"");
        try { File.Delete(MarkerPath); } catch { }
    }

    private static bool AddRule(string name, string protocol, string ranges) =>
        Netsh($"advfirewall firewall add rule name=\"{name}\" dir=out action=block "
              + $"protocol={protocol} remoteport=53 remoteip={ranges} enable=yes profile=any");

    private static bool Netsh(string arguments)
    {
        try
        {
            var psi = new ProcessStartInfo("netsh", arguments)
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            using var process = Process.Start(psi);
            if (process == null) return false;
            string output = process.StandardOutput.ReadToEnd();
            process.StandardError.ReadToEnd();
            if (!process.WaitForExit(15000)) return false;
            if (process.ExitCode != 0)
            {
                Log.Debug("DnsLeak", $"netsh {arguments.Split(' ')[2]} -> {process.ExitCode}: "
                                     + output.Trim().Replace("\r\n", " "));
                return false;
            }
            return true;
        }
        catch (Exception ex)
        {
            Log.Warn("DnsLeak", $"netsh failed: {ex.Message}");
            return false;
        }
    }
}
