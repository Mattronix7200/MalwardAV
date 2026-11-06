using System.Text;

namespace Malward.NetworkScanner.AdBlock;

public static class AdRedirects
{
    public sealed record Resource(byte[] Body, string ContentType);

    private static readonly byte[] Gif1x1 = Convert.FromBase64String(
        "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7");

    private static readonly byte[] Png1x1 = Convert.FromBase64String(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==");

    private static readonly byte[] SilentMp3 = BuildSilentMp3();

    private static byte[] BuildSilentMp3()
    {
        const int frames = 4, frameSize = 104;
        var buf = new byte[frames * frameSize];
        for (int i = 0; i < frames; i++)
        {
            int at = i * frameSize;
            buf[at] = 0xFF; buf[at + 1] = 0xFB; buf[at + 2] = 0x10; buf[at + 3] = 0xC0;
        }
        return buf;
    }

    private static Resource Js(string code) => new(Encoding.UTF8.GetBytes(code), "application/javascript; charset=utf-8");
    private static Resource Txt(string s) => new(Encoding.UTF8.GetBytes(s), "text/plain; charset=utf-8");
    private static Resource Html(string s) => new(Encoding.UTF8.GetBytes(s), "text/html; charset=utf-8");
    private static Resource Xml(string s) => new(Encoding.UTF8.GetBytes(s), "text/xml; charset=utf-8");

    private const string WpQaf ="""
        (function(){try{
          var w=self;
          w.$pbjsBefore=w.$pbjsBefore||0;
          w.$pbjsAfter=w.$pbjsBefore;
        }catch(e){}})();
""";

    private const string AdsByGoogle ="""
        (function(){try{
          var w=window;
          w.adsbygoogle=w.adsbygoogle||[];
          if(typeof w.adsbygoogle.push!=='function'||!w.adsbygoogle.loaded){
            w.adsbygoogle={loaded:true,push:function(){ try{
              var els=document.querySelectorAll('ins.adsbygoogle:not([data-adsbygoogle-status])');
              for(var i=0;i<els.length;i++){ els[i].setAttribute('data-adsbygoogle-status','done'); }
            }catch(e){} }};
          }
          w.google_jobrunner={};
          w.__gppSupported=true;
        }catch(e){}})();
""";

    public const string GoogleIma ="""
        (function(){try{
          var W=window, g=W.google=W.google||{};
          function noop(){}
          function Emitter(){ this._l={}; }
          Emitter.prototype.addEventListener=function(t,f){ (this._l[t]=this._l[t]||[]).push(f); };
          Emitter.prototype.removeEventListener=function(t,f){
            var a=this._l[t]; if(!a) return; var i=a.indexOf(f); if(i>=0) a.splice(i,1); };
          Emitter.prototype.removeAllListeners=function(){ this._l={}; };
          Emitter.prototype._emit=function(ev){
            var a=(this._l[ev.type]||[]).slice();
            for(var i=0;i<a.length;i++){ try{ a[i](ev); }catch(e){} } };
          var ima={};
          function AdError(msg,code,type){ this._m=msg; this._c=code; this._t=type; }
          AdError.prototype={ getErrorCode:function(){return this._c;},
            getInnerError:function(){return null;}, getMessage:function(){return this._m;},
            getType:function(){return this._t;}, getVastErrorCode:function(){return this._c;},
            toString:function(){return 'AdError '+this._c+': '+this._m;} };
          ima.AdError=AdError;
          ima.AdError.ErrorCode={ VAST_NO_ADS_AFTER_WRAPPER:303, UNKNOWN_AD_RESPONSE:1010,
            VAST_EMPTY_RESPONSE:1009 };
          ima.AdError.Type={ AD_LOAD:'adLoadError', AD_PLAY:'adPlayError' };
          function AdErrorEvent(err,ctx){ this.type='adError'; this._e=err; this._x=ctx; }
          AdErrorEvent.prototype={ getError:function(){return this._e;},
            getUserRequestContext:function(){return this._x||{};} };
          ima.AdErrorEvent=AdErrorEvent;
          ima.AdErrorEvent.Type={ AD_ERROR:'adError' };
          ima.AdEvent=function(t){ this.type=t; };
          ima.AdEvent.prototype={ getAd:function(){return null;}, getAdData:function(){return {};} };
          ima.AdEvent.Type={ AD_BREAK_READY:'adBreakReady', AD_METADATA:'adMetadata',
            ALL_ADS_COMPLETED:'allAdsCompleted', CLICK:'click', COMPLETE:'complete',
            CONTENT_PAUSE_REQUESTED:'contentPauseRequested',
            CONTENT_RESUME_REQUESTED:'contentResumeRequested', DURATION_CHANGE:'durationChange',
            FIRST_QUARTILE:'firstQuartile', IMPRESSION:'impression', INTERACTION:'interaction',
            LINEAR_CHANGED:'linearChanged', LOADED:'loaded', LOG:'log', MIDPOINT:'midpoint',
            PAUSED:'pause', RESUMED:'resume', SKIPPABLE_STATE_CHANGED:'skippableStateChanged',
            SKIPPED:'skip', STARTED:'start', THIRD_QUARTILE:'thirdQuartile',
            USER_CLOSE:'userClose', VOLUME_CHANGED:'volumeChange', VOLUME_MUTED:'mute' };
          ima.AdDisplayContainer=function(){};
          ima.AdDisplayContainer.prototype={ initialize:noop, destroy:noop };
          ima.AdsRequest=function(){};
          ima.AdsRequest.prototype={ setAdWillAutoPlay:noop, setAdWillPlayMuted:noop,
            setContinuousPlayback:noop };
          ima.AdsRenderingSettings=function(){};
          ima.AdsRenderingSettings.prototype={};
          function AdsManager(){ Emitter.call(this); }
          AdsManager.prototype=Object.create(Emitter.prototype);
          AdsManager.prototype.init=noop;
          AdsManager.prototype.start=function(){
            var self=this;
            setTimeout(function(){ self._emit(new ima.AdEvent('allAdsCompleted')); },0);
          };
          AdsManager.prototype.destroy=noop;
          AdsManager.prototype.discardAdBreak=noop;
          AdsManager.prototype.pause=noop;
          AdsManager.prototype.resume=noop;
          AdsManager.prototype.resize=noop;
          AdsManager.prototype.setVolume=noop;
          AdsManager.prototype.stop=noop;
          AdsManager.prototype.skip=noop;
          AdsManager.prototype.getVolume=function(){return 1;};
          AdsManager.prototype.getRemainingTime=function(){return 0;};
          AdsManager.prototype.getCuePoints=function(){return [];};
          AdsManager.prototype.getAdSkippableState=function(){return false;};
          AdsManager.prototype.isCustomClickTrackingUsed=function(){return false;};
          AdsManager.prototype.isCustomPlaybackUsed=function(){return false;};
          AdsManager.prototype.updateAdsRenderingSettings=noop;
          ima.AdsManager=AdsManager;
          ima.AdsManagerLoadedEvent=function(){ this.type='adsManagerLoaded'; };
          ima.AdsManagerLoadedEvent.prototype={
            getAdsManager:function(){ return new AdsManager(); },
            getUserRequestContext:function(){ return {}; } };
          ima.AdsManagerLoadedEvent.Type={ ADS_MANAGER_LOADED:'adsManagerLoaded' };
          function AdsLoader(){ Emitter.call(this); }
          AdsLoader.prototype=Object.create(Emitter.prototype);
          AdsLoader.prototype.contentComplete=noop;
          AdsLoader.prototype.destroy=noop;
          AdsLoader.prototype.getSettings=function(){ return ima.settings; };
          AdsLoader.prototype.getVersion=function(){ return '3.0.0'; };
          AdsLoader.prototype.requestAds=function(req){
            var self=this;
            setTimeout(function(){
              var err=new AdError('No ads available', 1009, 'adLoadError');
              self._emit(new AdErrorEvent(err, req && req.userRequestContext));
            },0);
          };
          ima.AdsLoader=AdsLoader;
          ima.settings={ setLocale:noop, setPlayerType:noop, setPlayerVersion:noop,
            setAutoPlayAdBreaks:noop, setNumRedirects:noop, setVpaidMode:noop,
            setDisableCustomPlaybackForIOS10Plus:noop, setCookiesEnabled:noop,
            setSessionId:noop, setPpid:noop, getPlayerType:function(){return '';} };
          ima.ViewMode={ NORMAL:'normal', FULLSCREEN:'fullscreen' };
          ima.UiElements={ AD_ATTRIBUTION:'adAttribution', COUNTDOWN:'countdown' };
          ima.ImaSdkSettings=function(){ return ima.settings; };
          ima.ImaSdkSettings.CompanionBackfillMode={ ALWAYS:'always', ON_MASTER_AD:'on_master_ad' };
          ima.ImaSdkSettings.VpaidMode={ DISABLED:0, ENABLED:1, INSECURE:2 };
          ima.VERSION='3.0.0';
          ima.OmidVerificationVendor={ OTHER:1, GOOGLE:2 };
          g.ima=ima;
        }catch(e){}})();
""";

    private const string Gpt ="""
        (function(){try{
          var W=window; function noop(){} function noopThis(){return this;}
          function Slot(path,id){ this._p=path; this._id=id; }
          Slot.prototype={ addService:noopThis, defineSizeMapping:noopThis, setCollapseEmptyDiv:noopThis,
            setTargeting:noopThis, setSafeFrameConfig:noopThis, setClickUrl:noopThis, setCategoryExclusion:noopThis,
            clearCategoryExclusions:noopThis, clearTargeting:noopThis, updateTargetingFromMap:noopThis,
            get:function(){return null;}, getAdUnitPath:function(){return this._p||'';},
            getSlotElementId:function(){return this._id||'';}, getDomId:function(){return this._id||'';},
            getTargeting:function(){return [];}, getTargetingKeys:function(){return [];},
            getResponseInformation:function(){return null;}, getEscapedQemQueryId:function(){return '';},
            getHtml:function(){return '';}, getName:function(){return this._p||'';},
            getSlotId:function(){return {getDomId:function(){return this._id||'';},getId:function(){return this._id||'';}};},
            getServices:function(){return [];}, getSizes:function(){return [];}, getFirstLook:function(){return 0;},
            getOutOfPage:function(){return false;}, getContentUrl:function(){return '';}, getClickUrl:function(){return '';} };
          function Service(){}
          Service.prototype={ addEventListener:noopThis, removeEventListener:noopThis, enable:noop, disableInitialLoad:noop,
            enableSingleRequest:noopThis, enableAsyncRendering:noopThis, enableLazyLoad:noopThis, enableVideoAds:noopThis,
            collapseEmptyDivs:noopThis, setCentering:noopThis, setTargeting:noopThis, clearTargeting:noopThis,
            setRequestNonPersonalizedAds:noopThis, setPublisherProvidedId:noopThis, setSafeFrameConfig:noopThis,
            setPrivacySettings:noopThis, setForceSafeFrame:noopThis, setCategoryExclusion:noopThis,
            clearCategoryExclusions:noopThis, updateCorrelator:noopThis, refresh:noop, clear:function(){return true;},
            display:noop, getSlots:function(){return [];}, get:function(){return null;}, set:noopThis,
            getTargeting:function(){return [];}, getTargetingKeys:function(){return [];}, isInitialLoadDisabled:function(){return true;},
            setVideoContent:noopThis, definePassback:function(){return null;}, defineOutOfPagePassback:function(){return null;} };
          var pubads=new Service();
          var gt = W.googletag = W.googletag || {};
          gt.apiReady = true; gt.cmd = gt.cmd || [];
          gt.pubads = function(){ return pubads; };
          gt.content = function(){ return {setContent:noop}; };
          gt.companionAds = function(){ return new Service(); };
          gt.defineSlot = function(p,s,i){ return new Slot(p,i); };
          gt.defineOutOfPageSlot = function(p,i){ return new Slot(p,i); };
          gt.defineUnit = gt.defineSlot;
          gt.destroySlots = noop; gt.display = noop; gt.enableServices = noop; gt.disablePublisherConsole = noop;
          gt.enums = {OutOfPageFormat:{BOTTOM_ANCHOR:2,INTERSTITIAL:5,REWARDED:4,TOP_ANCHOR:3},TrafficSource:{ORGANIC:1,PURCHASED:2}};
          gt.getVersion = function(){ return '0'; };
          gt.sizeMapping = function(){ var b={addSize:function(){return b;},build:function(){return [];}}; return b; };
          gt.setAdIframeTitle = noop; gt.setConfig = noop; gt.getConfig = function(){ return {}; };
          gt.openConsole = noop; gt.secureSignalProviders = gt.secureSignalProviders || [];
          var q = gt.cmd; gt.cmd = { push:function(f){ try{ if(typeof f==='function') f(); }catch(e){} return 1; } };
          if (Array.isArray(q)) { for (var i=0;i<q.length;i++) { try{ if(typeof q[i]==='function') q[i](); }catch(e){} } }
        }catch(e){}})();
""";

    private const string Apstag ="""
        (function(){try{
          var W=window; function noop(){}
          W.apstag = {
            _Q: [], init: noop, fetchBids: function(cfg, cb){ try{ if(typeof cb==='function') cb([]); }catch(e){} },
            setDisplayBids: noop, targetingKeys: function(){ return []; }, thirdPartyData: {},
            punt: noop, debug: noop, dpa: noop, rpa: noop, upa: noop
          };
        }catch(e){}})();
""";

    private const string Gtm ="""
        (function(){try{
          var W=window; W.dataLayer = W.dataLayer || [];
          if (typeof W.dataLayer.push !== 'function') W.dataLayer.push = function(){ return 1; };
          W.gtag = W.gtag || function(){};
          W.google_tag_manager = W.google_tag_manager || {};
        }catch(e){}})();
""";

    private const string Ga ="""
        (function(){try{
          var W=window; function noop(){}
          var ga = W[W.GoogleAnalyticsObject || 'ga'];
          if (typeof ga !== 'function') { ga = function(){ var a=arguments; try{
              if (typeof a[a.length-1]==='function') a[a.length-1]();
              else if (a[1] && typeof a[1].hitCallback === 'function') a[1].hitCallback();
            }catch(e){} }; }
          ga.create = function(){ return { get:noop, set:noop, send:noop }; };
          ga.getByName = function(){ return null; }; ga.getAll = function(){ return []; };
          ga.remove = noop; ga.loaded = true;
          W.ga = ga; W.GoogleAnalyticsObject = 'ga';
          W.gaplugins = W.gaplugins || {};
          W.dataLayer = W.dataLayer || []; W.gtag = W.gtag || function(){};
        }catch(e){}})();
""";

    private static readonly Resource JsGpt = Js(Gpt);
    private static readonly Resource JsApstag = Js(Apstag);
    private static readonly Resource JsGtm = Js(Gtm);
    private static readonly Resource JsGa = Js(Ga);
    private static readonly Resource JsAdsByGoogle = Js(AdsByGoogle);
    private static readonly Resource JsGoogleIma = Js(GoogleIma);
    private static readonly Resource JsWpQaf = Js(WpQaf);

    private static readonly Dictionary<string, Resource> Map = new(StringComparer.OrdinalIgnoreCase)
    {

        ["googletagservices_gpt.js"] = JsGpt, ["googletagservices-gpt"] = JsGpt,
        ["googletagservices_gpt"] = JsGpt, ["gpt.js"] = JsGpt,
        ["amazon_apstag.js"] = JsApstag, ["amazon-apstag"] = JsApstag, ["amazon_apstag"] = JsApstag,
        ["googletagmanager_gtm.js"] = JsGtm, ["googletagmanager-gtm"] = JsGtm, ["googletagmanager_gtm"] = JsGtm,
        ["google-analytics_analytics.js"] = JsGa, ["google-analytics-analytics"] = JsGa,
        ["google-analytics_analytics"] = JsGa, ["google-analytics_ga.js"] = JsGa,
        ["googletagservices_gpt.js:5"] = JsGpt,
        ["wp-qaf.js"] = JsWpQaf, ["wp_qaf.js"] = JsWpQaf, ["wp-qaf"] = JsWpQaf,

        ["noop.css"] = new(Array.Empty<byte>(), "text/css; charset=utf-8"),
        ["noopcss"] = new(Array.Empty<byte>(), "text/css; charset=utf-8"),
        ["abp-resource:blank-css"] = new(Array.Empty<byte>(), "text/css; charset=utf-8"),
        ["noopjs"] = Js(";"), ["noop.js"] = Js(";"), ["noop"] = Js(";"),
        ["abp-resource:blank-js"] = Js(";"),
        ["nooptext"] = Txt(""), ["noop.txt"] = Txt(""), ["abp-resource:blank-text"] = Txt(""),
        ["noopjson"] = new(Encoding.UTF8.GetBytes("{}"), "application/json; charset=utf-8"),
        ["1x1.gif"] = new(Gif1x1, "image/gif"), ["1x1-transparent.gif"] = new(Gif1x1, "image/gif"),
        ["abp-resource:blank-gif"] = new(Gif1x1, "image/gif"),
        ["2x2.png"] = new(Png1x1, "image/png"), ["3x2.png"] = new(Png1x1, "image/png"),
        ["32x32.png"] = new(Png1x1, "image/png"), ["2x2-transparent.png"] = new(Png1x1, "image/png"),
        ["3x2-transparent.png"] = new(Png1x1, "image/png"), ["32x32-transparent.png"] = new(Png1x1, "image/png"),
        ["abp-resource:blank-png"] = new(Png1x1, "image/png"),
        ["noopframe"] = Html("<html><head></head><body></body></html>"),
        ["noop.html"] = Html("<html><head></head><body></body></html>"),
        ["abp-resource:blank-html"] = Html("<html><head></head><body></body></html>"),

        ["noopmp3-0.1s"] = new(SilentMp3, "audio/mpeg"),
        ["noop-0.1s.mp3"] = new(SilentMp3, "audio/mpeg"),
        ["abp-resource:blank-mp3"] = new(SilentMp3, "audio/mpeg"),
        ["noopmp4-1s"] = new(Array.Empty<byte>(), "video/mp4"),
        ["noop-1s.mp4"] = new(Array.Empty<byte>(), "video/mp4"),

        ["noopvast-2.0"] = Xml("<VAST version=\"2.0\"></VAST>"),
        ["noopvast-3.0"] = Xml("<VAST version=\"3.0\"></VAST>"),
        ["noopvast-4.0"] = Xml("<VAST version=\"4.0\"></VAST>"),
        ["noopvmap-1.0"] = Xml("<vmap:VMAP xmlns:vmap=\"http://www.iab.net/videosuite/vmap\" version=\"1.0\"></vmap:VMAP>"),
        ["noopvmap"] = Xml("<vmap:VMAP xmlns:vmap=\"http://www.iab.net/videosuite/vmap\" version=\"1.0\"></vmap:VMAP>"),
        ["googlesyndication_adsbygoogle.js"] = JsAdsByGoogle,
        ["googlesyndication-adsbygoogle"] = JsAdsByGoogle,
        ["google-ima.js"] = JsGoogleIma, ["google-ima3"] = JsGoogleIma, ["google-ima"] = JsGoogleIma,
    };

    private static readonly char[] KoniecSciezki = { '?', '#' };

    internal static bool IsAdInventory(string path, string url)
    {
        if (path.Contains("/vast", StringComparison.OrdinalIgnoreCase)
         || path.Contains("/vpaid", StringComparison.OrdinalIgnoreCase)
         || path.Contains("/gampad/ads", StringComparison.OrdinalIgnoreCase)
         || path.Contains("/gampad/live/ads", StringComparison.OrdinalIgnoreCase)
         || path.Contains("/pagead/ads", StringComparison.OrdinalIgnoreCase)
         || path.EndsWith("/getvast", StringComparison.OrdinalIgnoreCase)) return true;

        int q = url.IndexOf('?');
        if (q < 0) return false;
        var query = url[(q + 1)..];
        return query.Contains("output=vast", StringComparison.OrdinalIgnoreCase)
            || query.Contains("output=xml_vast", StringComparison.OrdinalIgnoreCase)
            || query.Contains("vast_version=", StringComparison.OrdinalIgnoreCase)
            || query.Contains("ad_type=video", StringComparison.OrdinalIgnoreCase)

            || (query.Contains("iu=", StringComparison.OrdinalIgnoreCase)
                && query.Contains("sz=", StringComparison.OrdinalIgnoreCase));
    }

    internal static bool IsAdSchedule(string path, string url) =>
        path.Contains("/vmap", StringComparison.OrdinalIgnoreCase)
     || url.Contains("output=vmap", StringComparison.OrdinalIgnoreCase)
     || url.Contains("ad_rule=1", StringComparison.OrdinalIgnoreCase)
     || (url.Contains("vmap", StringComparison.OrdinalIgnoreCase)
         && url.Contains("ad", StringComparison.OrdinalIgnoreCase));

    public static Resource Neutral(AdResourceType type, string url)
    {
        var path = url;
        int q = path.IndexOfAny(KoniecSciezki);
        if (q > 0) path = path[..q];

        if (IsAdSchedule(path, url)) return Map["noopvmap-1.0"];
        if (IsAdInventory(path, url)) return Map["noopvast-3.0"];

        if (type.HasFlag(AdResourceType.Script) || path.EndsWith(".js", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".mjs", StringComparison.OrdinalIgnoreCase))
            return Map["noop.js"];
        if (type.HasFlag(AdResourceType.Stylesheet) || path.EndsWith(".css", StringComparison.OrdinalIgnoreCase))
            return Map["noop.css"];
        if (type.HasFlag(AdResourceType.Image) || path.EndsWith(".gif", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".png", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".jpg", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".jpeg", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".webp", StringComparison.OrdinalIgnoreCase))
            return Map["1x1.gif"];
        if (path.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            return Map["noopjson"];

        if (path.EndsWith(".mp3", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".m4a", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".aac", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".ogg", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".opus", StringComparison.OrdinalIgnoreCase))
            return Map["noop-0.1s.mp3"];

        if (type.HasFlag(AdResourceType.XmlHttpRequest) &&
            path.LastIndexOf('.') <= path.LastIndexOf('/'))
            return Map["noopjson"];
        if (type.HasFlag(AdResourceType.XmlHttpRequest) || type.HasFlag(AdResourceType.Ping) ||
            type.HasFlag(AdResourceType.Other))
            return Map["noop.txt"];
        if (type.HasFlag(AdResourceType.Media))
            return Map["noop-1s.mp4"];
        return Map["noop.txt"];
    }

    public static Resource? GuessByUrl(string url)
    {
        if (string.IsNullOrEmpty(url)) return null;
        var u = url.ToLowerInvariant();
        if (u.Contains("/gpt.js") || u.Contains("googletagservices.com/tag/js/gpt")) return JsGpt;
        if (u.Contains("apstag.js")) return JsApstag;
        if (u.Contains("adsbygoogle.js")) return JsAdsByGoogle;
        if (u.Contains("googletagmanager.com/gtm.js") || u.Contains("googletagmanager.com/gtag/js")) return JsGtm;
        if (u.Contains("google-analytics.com/analytics.js") || u.Contains("google-analytics.com/ga.js")
            || u.Contains("googletagmanager.com/gtag/destination")) return JsGa;
        if (u.Contains("imasdk.googleapis.com") && u.Contains("ima3")) return JsGoogleIma;
        if (u.Contains("rek.www.wp.pl/qaf.js")) return JsWpQaf;
        return null;
    }

    public static Resource? Get(string? name)
    {
        if (string.IsNullOrEmpty(name)) return null;

        int colon = name.LastIndexOf(':');
        if (colon > 0 && int.TryParse(name[(colon + 1)..], out _)) name = name[..colon];
        name = name.Trim();
        if (name.Length == 0) return null;

        if (Map.TryGetValue(name, out var r)) return r;

        foreach (var alt in new[] { name.Replace('-', '_'), name.Replace('_', '-'),
                                    name + ".js", name.Replace(".js", "") })
            if (Map.TryGetValue(alt, out r)) return r;

        if (name.EndsWith(".css", StringComparison.OrdinalIgnoreCase) || name.Contains("css", StringComparison.OrdinalIgnoreCase))
            return new(Array.Empty<byte>(), "text/css; charset=utf-8");
        if (name.EndsWith(".gif", StringComparison.OrdinalIgnoreCase)) return new(Gif1x1, "image/gif");
        if (name.EndsWith(".png", StringComparison.OrdinalIgnoreCase)) return new(Png1x1, "image/png");
        if (name.Contains("json", StringComparison.OrdinalIgnoreCase))
            return new(Encoding.UTF8.GetBytes("{}"), "application/json; charset=utf-8");
        if (name.Contains("html", StringComparison.OrdinalIgnoreCase) || name.Contains("frame", StringComparison.OrdinalIgnoreCase))
            return Html("<html><head></head><body></body></html>");
        if (name.Contains("text", StringComparison.OrdinalIgnoreCase)) return Txt("");
        if (name.EndsWith(".js", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("js", StringComparison.OrdinalIgnoreCase)) return Js(";");
        return null;
    }
}
