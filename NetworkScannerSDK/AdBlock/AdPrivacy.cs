using System.Text;

namespace Malward.NetworkScanner.AdBlock;

public static class AdPrivacy
{

    public sealed class Options
    {
        public bool StripUrlParams = true;
        public bool HideSearchQueries = true;
        public bool DoNotTrack = true;
        public bool ThirdPartyCookieTtl = true;
        public int ThirdPartyCookieMinutes = 180;
        public bool NoThirdPartyCache;
        public bool BlockPush = true;
        public bool BlockGeolocation = true;
        public bool StripXClientData = true;
        public bool BlockTrackers = true;
    }

    private static readonly string[] TrackerHosts =
    {
        "google-analytics.com", "analytics.google.com", "googletagmanager.com",
        "doubleclick.net", "googlesyndication.com", "googleadservices.com", "adservice.google.com",
        "scorecardresearch.com", "quantserve.com", "quantcount.com", "chartbeat.com", "chartbeat.net",
        "hotjar.com", "hotjar.io", "mouseflow.com", "crazyegg.com", "luckyorange.com", "fullstory.com",
        "mixpanel.com", "segment.com", "segment.io", "amplitude.com", "heap.io", "heapanalytics.com",
        "kissmetrics.com", "kissmetrics.io", "matomo.cloud", "statcounter.com", "clicky.com",
        "newrelic.com", "nr-data.net", "bugsnag.com", "sentry.io", "logrocket.com", "logrocket.io",
        "branch.io", "adjust.com", "appsflyer.com", "kochava.com", "singular.net",
        "criteo.com", "criteo.net", "taboola.com", "outbrain.com", "sharethrough.com",
        "pubmatic.com", "rubiconproject.com", "openx.net", "casalemedia.com", "adnxs.com",
        "33across.com", "bidswitch.net", "smartadserver.com", "teads.tv", "yieldmo.com",
        "moatads.com", "adsafeprotected.com", "doubleverify.com", "omnitagjs.com",
        "krxd.net", "bluekai.com", "demdex.net", "everesttech.net", "omtrdc.net", "2o7.net",
        "agkn.com", "rlcdn.com", "crwdcntrl.net", "exelator.com", "eyeota.net", "tapad.com",
        "mathtag.com", "turn.com", "adform.net", "adsrvr.org", "simpli.fi",
        "hs-analytics.net", "hubspot.com", "marketo.net", "pardot.com", "omniconvert.com",
        "yandex.ru/metrika", "mc.yandex.ru", "top-fwz1.mail.ru", "vk.com/rtrg",
        "clarity.ms", "browser-intake-datadoghq.com", "cdn.mxpnl.com", "tiktokcdn.com/analytics",
        "analytics.tiktok.com", "ads.linkedin.com", "px.ads.linkedin.com", "snap.licdn.com",
        "connect.facebook.net", "pixel.facebook.com", "an.facebook.com",
        "ads-twitter.com", "static.ads-twitter.com", "analytics.twitter.com",
        "gemius.pl", "hit.gemius.pl", "spis.gemius.pl", "redir.gemius.pl",
        "wp.pl/statystyki", "stat.wp.pl", "hit.stat24.com", "stat24.com",
        "onet.pl/_stat", "stat.onet.pl", "iplsc.com/stat"
    };

    public static readonly string[] AdApiPermissions =
    {
        "browsing-topics", "join-ad-interest-group", "run-ad-auction",
        "private-state-token-issuance", "private-state-token-redemption",

    };

    public static bool IsTracker(string host)
    {
        if (string.IsNullOrEmpty(host)) return false;
        foreach (var t in TrackerHosts)
        {
            if (t.Contains('/')) continue;
            if (host.Equals(t, StringComparison.OrdinalIgnoreCase)) return true;
            if (host.Length > t.Length && host[host.Length - t.Length - 1] == '.' &&
                host.EndsWith(t, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    public static bool IsTrackerUrl(string url)
    {
        foreach (var t in TrackerHosts)
            if (t.Contains('/') && url.Contains(t, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static readonly HashSet<string> TrackingParams = new(StringComparer.OrdinalIgnoreCase)
    {
        "utm_source","utm_medium","utm_campaign","utm_term","utm_content","utm_id","utm_name",
        "utm_cid","utm_reader","utm_swu","utm_social","utm_social-type","utm_brand",
        "fbclid","gclid","gclsrc","dclid","wbraid","gbraid","msclkid","yclid","twclid",
        "igshid","mc_eid","mc_cid","_openstat","vero_id","vero_conv","oly_anon_id","oly_enc_id",
        "hsCtaTracking","__hssc","__hstc","__hsfp","_hsenc","_hsmi","mkt_tok",
        "ml_subscriber","ml_subscriber_hash","rb_clickid","s_cid","epik","irclickid",
        "ttclid","li_fat_id","at_recipient_id","at_recipient_list","ef_id","s_kwcid"
    };

    private static readonly string[] SearchHosts =
    {
        "google.", "bing.com", "duckduckgo.com", "yahoo.com", "yandex.", "search.brave.com",
        "ecosia.org", "startpage.com", "qwant.com"
    };

    public static string? StripTrackingParams(string url)
    {
        int q = url.IndexOf('?');
        if (q < 0) return null;

        int hash = url.IndexOf('#', q);
        var query = hash < 0 ? url[(q + 1)..] : url[(q + 1)..hash];
        var fragment = hash < 0 ? "" : url[hash..];
        if (query.Length == 0) return null;

        var kept = new List<string>();
        bool removed = false;
        foreach (var pair in query.Split('&'))
        {
            if (pair.Length == 0) continue;
            int eq = pair.IndexOf('=');
            var name = eq < 0 ? pair : pair[..eq];
            if (TrackingParams.Contains(name)) { removed = true; continue; }
            kept.Add(pair);
        }
        if (!removed) return null;

        var sb = new StringBuilder(url.Length).Append(url, 0, q);
        if (kept.Count > 0) sb.Append('?').Append(string.Join("&", kept));
        sb.Append(fragment);
        return sb.ToString();
    }

    public static bool IsSearchEngine(string host)
    {
        foreach (var s in SearchHosts)
            if (host.Contains(s, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    public static string? TrimSearchReferer(string referer)
    {
        if (!Uri.TryCreate(referer, UriKind.Absolute, out var u)) return null;
        if (!IsSearchEngine(u.Host)) return null;
        if (u.Query.Length == 0) return null;
        return u.GetLeftPart(UriPartial.Path);
    }

    public static string? LimitCookieLifetime(string setCookie, int minutes)
    {
        if (minutes <= 0) return "";

        var parts = setCookie.Split(';');
        var kept = new List<string>();
        foreach (var raw in parts)
        {
            var p = raw.Trim();
            if (p.StartsWith("expires=", StringComparison.OrdinalIgnoreCase)) continue;
            if (p.StartsWith("max-age=", StringComparison.OrdinalIgnoreCase)) continue;
            kept.Add(p);
        }
        kept.Add("Max-Age=" + (minutes * 60));
        return string.Join("; ", kept);
    }

    public static string ApiBlockScript(bool blockPush, bool blockGeo)
    {
        if (!blockPush && !blockGeo) return "";
        var sb = new StringBuilder("(function(){try{", 1024);
        if (blockPush)
            sb.Append("if(window.Notification){try{Object.defineProperty(Notification,'permission',{get:function(){return 'denied';}});}catch(e){}")
              .Append("try{Notification.requestPermission=function(cb){var p=Promise.resolve('denied');if(cb)try{cb('denied');}catch(e){}return p;};}catch(e){}}")
              .Append("try{if(window.PushManager&&PushManager.prototype)PushManager.prototype.subscribe=function(){return Promise.reject(new Error('blocked'));};}catch(e){}");
        if (blockGeo)
            sb.Append("try{if(navigator.geolocation){navigator.geolocation.getCurrentPosition=function(s,e){if(e)try{e({code:1,message:'blocked',PERMISSION_DENIED:1});}catch(x){}};")
              .Append("navigator.geolocation.watchPosition=function(s,e){if(e)try{e({code:1,message:'blocked',PERMISSION_DENIED:1});}catch(x){}return 0;};}}catch(e){}");
        sb.Append("}catch(e){}})();");
        return sb.ToString();
    }
}
