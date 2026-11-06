namespace Malward.NetworkScanner.AdBlock;

public static class AdRuleHash
{
    public static string NormalizeHost(string host)
    {
        host = host.Trim().TrimEnd('.').ToLowerInvariant();
        int slash = host.IndexOf('/');
        if (slash >= 0) host = host[..slash];
        int colon = host.IndexOf(':');
        if (colon >= 0) host = host[..colon];
        return host;
    }

    public static ulong Fnv1a(string s)
    {
        const ulong offset = 14695981039346656037UL;
        const ulong prime = 1099511628211UL;
        ulong h = offset;
        foreach (char c in s)
        {
            h ^= (byte)c;
            h *= prime;
        }
        return h;
    }

    public static IEnumerable<string> Suffixes(string host)
    {
        var cur = host;
        while (true)
        {
            yield return cur;
            int dot = cur.IndexOf('.');
            if (dot < 0) yield break;
            cur = cur[(dot + 1)..];
        }
    }
}
