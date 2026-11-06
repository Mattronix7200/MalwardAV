namespace Malward.NetworkScanner.AdBlock;

public static class AdCaptcha
{
    private static readonly string[] Hosts =
    {
        "challenges.cloudflare.com",
        "hcaptcha.com",
        "recaptcha.net",
        "captcha-delivery.com",
        "geo.captcha-delivery.com",
        "arkoselabs.com",
        "funcaptcha.com",
        "client-api.arkoselabs.com",
        "geetest.com",
        "friendlycaptcha.com",
        "api.friendlycaptcha.com",
        "turnstile.cloudflare.com",
    };

    private static readonly string[] Paths =
    {
        "/recaptcha/",
        "/hcaptcha",
        "/turnstile/",
        "/cdn-cgi/challenge-platform/",
        "/cdn-cgi/bm/",
        "/captcha/",
        "/_Incapsula_Resource",
        "/akam/",
        "/px/",
    };

    public static bool IsChallengeHost(string host)
    {
        if (string.IsNullOrEmpty(host)) return false;
        var h = AdRuleHash.NormalizeHost(host);
        foreach (var known in Hosts)
        {
            if (h.Equals(known, StringComparison.OrdinalIgnoreCase)) return true;
            if (h.Length > known.Length && h[h.Length - known.Length - 1] == '.'
                && h.EndsWith(known, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    public static bool IsChallenge(string url, string host)
    {
        if (IsChallengeHost(host)) return true;
        if (string.IsNullOrEmpty(url)) return false;
        foreach (var fragment in Paths)
            if (url.Contains(fragment, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }
}
