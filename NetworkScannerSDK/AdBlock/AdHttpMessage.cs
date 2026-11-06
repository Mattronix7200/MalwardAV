using System.Text;

namespace Malward.NetworkScanner.AdBlock;

public sealed class AdHttpMessage
{
    public string StartLine = "";
    public readonly List<KeyValuePair<string, string>> Headers = new();

    public string Method = "";
    public string Target = "";
    public string Version = "HTTP/1.1";
    public int StatusCode;

    public static AdHttpMessage? ParseRequest(string head)
    {
        var m = Parse(head);
        if (m == null) return null;
        var parts = m.StartLine.Split(' ');
        if (parts.Length < 3) return null;
        m.Method = parts[0];
        m.Target = parts[1];
        m.Version = parts[2];
        return m;
    }

    public static AdHttpMessage? ParseResponse(string head)
    {
        var m = Parse(head);
        if (m == null) return null;
        var parts = m.StartLine.Split(' ');
        if (parts.Length < 2) return null;
        m.Version = parts[0];
        m.StatusCode = int.TryParse(parts[1], out var c) ? c : 0;
        return m;
    }

    private static AdHttpMessage? Parse(string head)
    {
        var lines = head.Replace("\r\n", "\n").Split('\n');
        if (lines.Length == 0 || lines[0].Length == 0) return null;

        var m = new AdHttpMessage { StartLine = lines[0] };
        for (int i = 1; i < lines.Length; i++)
        {
            var line = lines[i];
            if (line.Length == 0) break;
            int colon = line.IndexOf(':');
            if (colon <= 0) continue;
            m.Headers.Add(new KeyValuePair<string, string>(
                line[..colon].Trim(), line[(colon + 1)..].Trim()));
        }
        return m;
    }

    public string? Get(string name)
    {
        foreach (var h in Headers)
            if (string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase)) return h.Value;
        return null;
    }

    public bool Has(string name, string value)
    {
        var v = Get(name);
        return v != null && v.Contains(value, StringComparison.OrdinalIgnoreCase);
    }

    public bool IsChunked() => Has("Transfer-Encoding", "chunked");

    public long ContentLength()
    {
        var v = Get("Content-Length");
        return v != null && long.TryParse(v.Trim(), out var n) && n >= 0 ? n : -1;
    }

    public bool WantsClose() => Has("Connection", "close");

    public byte[] Serialize()
    {
        var sb = new StringBuilder(256);
        sb.Append(StartLine).Append("\r\n");
        foreach (var h in Headers) sb.Append(h.Key).Append(": ").Append(h.Value).Append("\r\n");
        sb.Append("\r\n");
        return Encoding.ASCII.GetBytes(sb.ToString());
    }
}
