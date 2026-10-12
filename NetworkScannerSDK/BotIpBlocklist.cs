using System;
using System.Collections.Generic;
using System.IO;

namespace Malward.NetworkScanner;

public sealed class BotIpBlocklist
{
    private readonly string _path;
    private readonly object _lock = new();

    private uint[] _ipv4 = Array.Empty<uint>();

    private HashSet<string> _other = new(StringComparer.Ordinal);
    private DateTime _mtimeUtc = DateTime.MinValue;

    public BotIpBlocklist(string path)
    {
        _path = path;
        Reload();
    }

    public bool IsEmpty { get { lock (_lock) return _ipv4.Length == 0 && _other.Count == 0; } }

    public bool Contains(string ip)
    {
        lock (_lock) { if (_ipv4.Length == 0 && _other.Count == 0) return false; }
        Reload();
        lock (_lock)
        {
            if (TryParseIpv4Exact(ip, out uint v))
            {
                if (_ipv4.Length > 0 && Array.BinarySearch(_ipv4, v) >= 0) return true;
            }
            return _other.Count > 0 && _other.Contains(ip);
        }
    }

    private void Reload()
    {
        try
        {
            if (!File.Exists(_path))
            {
                lock (_lock)
                {
                    _ipv4 = Array.Empty<uint>();
                    _other = new HashSet<string>(StringComparer.Ordinal);
                    _mtimeUtc = DateTime.MinValue;
                }
                return;
            }
            var mt = File.GetLastWriteTimeUtc(_path);
            lock (_lock) { if (mt == _mtimeUtc && (_ipv4.Length > 0 || _other.Count > 0)) return; }

            var ips = new List<uint>(1 << 16);
            var other = new HashSet<string>(StringComparer.Ordinal);
            foreach (var line in File.ReadLines(_path))
            {
                var t = line.Trim();
                if (t.Length == 0 || t.StartsWith('#')) continue;
                if (TryParseIpv4Exact(t, out uint v)) ips.Add(v);
                else other.Add(t);
            }

            var arr = ips.ToArray();
            Array.Sort(arr);
            arr = Dedup(arr);

            lock (_lock) { _ipv4 = arr; _other = other; _mtimeUtc = mt; }
        }
        catch {  }
    }

    private static uint[] Dedup(uint[] sorted)
    {
        if (sorted.Length < 2) return sorted;
        int w = 1;
        for (int i = 1; i < sorted.Length; i++)
            if (sorted[i] != sorted[w - 1]) sorted[w++] = sorted[i];
        if (w == sorted.Length) return sorted;
        var res = new uint[w];
        Array.Copy(sorted, res, w);
        return res;
    }

    private static bool TryParseIpv4Exact(string? s, out uint value)
    {
        value = 0;
        if (s == null) return false;
        int len = s.Length;
        if (len < 7 || len > 15) return false;

        uint acc = 0;
        int parts = 0, digits = 0, cur = 0;
        for (int i = 0; i < len; i++)
        {
            char c = s[i];
            if (c == '.')
            {
                if (digits == 0) return false;
                acc = (acc << 8) | (uint)cur;
                if (++parts > 3) return false;
                cur = 0; digits = 0;
            }
            else if (c >= '0' && c <= '9')
            {
                if (digits == 1 && cur == 0) return false;
                if (++digits > 3) return false;
                cur = cur * 10 + (c - '0');
                if (cur > 255) return false;
            }
            else return false;
        }
        if (parts != 3 || digits == 0) return false;
        value = (acc << 8) | (uint)cur;
        return true;
    }
}
