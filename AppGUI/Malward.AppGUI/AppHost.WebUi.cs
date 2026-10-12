using System;
using System.Text.Json;
using System.Text.Json.Nodes;
using Malward.AppGUI.Services;

namespace Malward.AppGUI;

public partial class AppHost
{
    private WebUiServer? _webUi;

    internal string? WebUiUrl => _webUi?.Url;

    internal bool WebMode
    {
        get
        {
            if (_webMode.HasValue) return _webMode.Value;
            bool web = false;
            try
            {
                var dir = System.IO.Path.Combine(_appDataDir, "data");
                if (System.IO.File.Exists(System.IO.Path.Combine(dir, "web-ui"))) web = true;
                else
                {
                    var plik = System.IO.Path.Combine(dir, "gui-settings.json");
                    if (System.IO.File.Exists(plik)
                        && System.Text.Json.Nodes.JsonNode.Parse(System.IO.File.ReadAllText(plik))
                           is System.Text.Json.Nodes.JsonObject o)
                        web = o["gui_mode"]?.GetValue<string>() == "web";
                }
            }
            catch { }
            _webMode = web;
            return web;
        }
    }
    private bool? _webMode;

    private void StartWebUiIfRequested()
    {
        if (!WebMode) return;
        StartWebUi();
        if (_webUi == null) return;

        CrashLog.Write("web-ui", null, $"otwórz w przeglądarce: {_webUi.Url}");
        _tray?.NotifyBalloon(Loc.T("Malward działa w tle"),
                           Loc.T("Interfejs otworzysz w przeglądarce — kliknij ikonę w zasobniku."),
                           () => OpenInBrowser());
        PostToJs("ui.mode", new { mode = "web" });
    }

    internal void OpenInBrowser(string? idZdarzenia = null)
    {
        var url = _webUi?.Url;
        if (string.IsNullOrEmpty(url)) return;
        if (!string.IsNullOrEmpty(idZdarzenia))
            url += "&ev=" + Uri.EscapeDataString(idZdarzenia) + "#/events";

        lock (_openLock)
        {
            var teraz = Environment.TickCount64;
            if (teraz - _lastOpenTick < OpenDebounceMs) return;
            _lastOpenTick = teraz;
        }

        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url)
            { UseShellExecute = true });
        }
        catch (Exception ex) { CrashLog.Write("web-ui", ex, "opening the browser"); }
    }

    private readonly object _openLock = new();
    private long _lastOpenTick;

    private const long OpenDebounceMs = 2000;

    private void StartWebUi()
    {
        if (_webUi != null) return;
        if (_assets is not { Loaded: true })
        {
            CrashLog.Write("web-ui", null, "asset pack not loaded — the web interface cannot start");
            return;
        }

        try
        {
            WebUiServer.ClearUploads();
            _webUi = new WebUiServer(_assets, ReceiveFromBrowser, 9099, () =>
            {
                var g = _guiSettings?.Read() ?? new Services.GuiSettings();
                return (g.Theme, g.Lang, EditionJson());
            });
            _webUi.Start();
            CrashLog.Write("web-ui", null, $"web interface listening on 127.0.0.1:{_webUi.Port}");
        }
        catch (Exception ex)
        {
            _webUi = null;
            CrashLog.Write("web-ui", ex, "starting the web interface");
        }
    }

    private void StopWebUi()
    {
        try { _webUi?.Dispose(); } catch { }
        _webUi = null;
    }

    private void ReceiveFromBrowser(string type, string json)
    {
        try
        {
            if (JsonNode.Parse(json) is not JsonObject node) return;
            Ui.Post((() =>
            {
                try { HandleMessage(type, node); }
                catch (Exception ex) { CrashLog.Write("web-ui", ex, type); }
            }));
        }
        catch (Exception ex) { CrashLog.Write("web-ui", ex, "parsing a message from the browser"); }
    }

    private void PushToBrowser(string type, object payload)
    {
        var srv = _webUi;
        if (srv == null) return;
        try { srv.Push(JsonSerializer.Serialize(new { type, payload }, _jsCamel)); }
        catch { }
    }
}
