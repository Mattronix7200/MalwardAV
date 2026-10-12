using System;
using System.Text.Json.Nodes;
using Malward.AppGUI.Services;

namespace Malward.AppGUI;

public partial class AppHost
{
    private bool _zdarzeniaPodpiete;

    private void HookEventCentre()
    {
        if (_zdarzeniaPodpiete) return;
        _zdarzeniaPodpiete = true;
        EventCentre.Changed += () =>
        {
            if (Ui.HasAccess) SendEvents();
            else Ui.Post((SendEvents));
        };
    }

    private void SendEvents()
    {
        try { PostToJs("events.list", new { items = EventCentre.ToJson() }); }
        catch {  }
    }

    private bool ObsluzKomunikatInterfejsu(string type)
    {
        if (type != "ui.webaddress.open") return false;
        OpenInBrowser();
        return true;
    }

    private bool ObsluzKomunikatZdarzen(string type, JsonObject? data)
    {
        switch (type)
        {
            case "events.read":
                SendEvents();
                return true;

            case "events.clear.handled":
                EventCentre.ClearHandled();
                return true;

            case "events.action":
            {
                var id = data?["id"]?.GetValue<string>() ?? "";
                var akcja = data?["action"]?.GetValue<string>() ?? "";
                bool wykonano;
                try { wykonano = EventCentre.Answer(id, akcja); }
                catch (Exception ex)
                {
                    CrashLog.Write("event-centre", ex, $"{id}/{akcja}");
                    PostToJs("toast", new { level = "warn",
                        msg = $"{Loc.T("Nie udało się wykonać akcji")}: {ex.Message}" });
                    SendEvents();
                    return true;
                }
                if (!wykonano)

                    PostToJs("toast", new { level = "info",
                        msg = Loc.T("To zdarzenie zostało już rozstrzygnięte.") });
                SendEvents();
                return true;
            }
        }
        return false;
    }
}
