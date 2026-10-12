using System;
using System.Linq;
using System.IO;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Malward.AppGUI.Services;

namespace Malward.AppGUI;

public partial class AppHost
{
    private void StartHipsAlerts()
    {
        try
        {
            _hipsAlerts = new HipsAlertWatcher(
                show: a =>
                {
                    if (Ui.HasAccess) ShowHipsAlert(a);
                    else Ui.Post((() => ShowHipsAlert(a)));
                },
                enabled: HipsNotificationsOn);
        }
        catch (Exception ex)
        {
            CrashLog.Write("HIPS", ex, "starting system-component protection notifications");
        }
    }

    private bool HipsNotificationsOn()
    {
        try
        {
            var s = _residentSettings?.Read();
            if (s?["notifications"] is JsonNode n) return n.GetValue<bool>();
        }
        catch { }
        return true;
    }

    private const bool _decideKinds = false;

    private bool ReportHipsToCentre(HipsAlertWatcher.Alert a, bool canFix)
    {
        try
        {
            string detekcja = string.IsNullOrWhiteSpace(a.RuleName) ? "HIPS.SystemChange" : a.RuleName;

            if (a.Blocked)
            {
                EventCentre.Report("hips", Loc.T("Zablokowano zmianę w systemie"),
                                   detekcja, a.Process, a.Where, a.Detail);
                return WebMode;
            }

            var akcje = new List<EventCentre.Choice>();
            var odpowiedzi = new Dictionary<string, Action>();
            if (canFix)
            {
                akcje.Add(new EventCentre.Choice("fix", "Napraw (cofnij zmianę)", Primary: true));
                odpowiedzi["fix"] = () => ApplyHipsFix(a);
            }
            akcje.Add(new EventCentre.Choice("allow", "Zezwól i dodaj wyjątek"));
            odpowiedzi["allow"] = () => AllowHips(a);

            var wpis = EventCentre.Ask("hips", Loc.T("Wykryto zmianę w systemie"),
                                       detekcja, a.Process, a.Where, a.Detail, akcje, odpowiedzi);
            return ReportByBalloon(wpis);
        }
        catch (Exception ex) { CrashLog.Write("HIPS", ex, "adding the event to the event centre"); }
        return false;
    }

    private void ShowHipsAlert(HipsAlertWatcher.Alert a)
    {
        try
        {
            bool dark = ResolveDark(_guiSettings?.Read()?.Theme ?? "auto");
            var icon  = AssetBytes(a.Blocked ? "shield.png" : "question.png")
                        ?? AssetBytes("warning.png");
            var logo  = AssetBytes("logo.png") ?? AssetBytes("ic-logo.png");

            bool canFix = !a.Blocked && a.Fix != null;

            if (ReportHipsToCentre(a, canFix)) return;

            Action? onFix = canFix ? () => ApplyHipsFix(a) : null;
            Action? onAllow = a.Blocked ? null : () => AllowHips(a);

            if (a.Blocked && !_decideKinds)
            {
                var wpis = new RichInfoPopupForm.Entry(
                    Title: "Zablokowano zmianę w systemie",
                    Detection: string.IsNullOrWhiteSpace(a.RuleName) ? "HIPS.SystemChange" : a.RuleName,
                    Path: string.IsNullOrWhiteSpace(a.Where) ? null : a.Where,
                    File: string.IsNullOrWhiteSpace(a.Kind) ? null : a.Kind,
                    Process: string.IsNullOrWhiteSpace(a.Process) ? null : a.Process,
                    Items: string.IsNullOrWhiteSpace(a.Detail) ? null : new[] { a.Detail });

                RichInfoPopupForm.Group Grupa() => new()
                {
                    Kind = "hips",
                    BannerText = Loc.T("Zablokowano szkodliwe działania oraz wycofano zmiany"),
                    HeaderColor = System.Drawing.Color.FromArgb(0xC0, 0x2A, 0x2A),

                    IconPng = AssetBytes("restoredfiles.png") ?? icon,
                    LogoPng = logo,
                    ButtonText = Loc.T("Wyświetl szczegóły zdarzenia"),
                    OnButton = () => OpenHipsEvents(),
                };

                var zywe = RichInfoPopupForm.Live;
                if (zywe != null && zywe.AppendLive("hips", wpis)) return;

                RichInfoPopupForm Zbuduj()
                {
                    var g = Grupa();
                    g.Entries.Clear();
                    g.Entries.Add(wpis);
                    return new RichInfoPopupForm(dark, g, autoDismissSec: 45);
                }

                if (ShieldPopupHub.Report("hips", "Zablokowano szkodliwe działania oraz wycofano zmiany",
                                          () => Zbuduj()))
                    return;

                Zbuduj().Show();
                return;
            }

            var pytanie = new HipsAlertForm.Info(a.RuleName, a.Detail, a.Where, a.Process, a.Kind, a.Blocked);

            var kolejka = HipsAlertForm.Live;
            if (kolejka != null && kolejka.Enqueue(pytanie, onFix, onAllow)) return;

            new HipsAlertForm(dark, pytanie, icon, logo, null,
                onFix, onAllow, () => OpenHipsEvents()).Show();
        }
        catch (Exception ex)
        {
            CrashLog.Write("HIPS", ex, "system-component protection event window");
        }
    }

    private void ApplyHipsFix(HipsAlertWatcher.Alert a)
    {
        var payload = a.Fix?.DeepClone() as JsonObject;
        if (payload == null) return;

        payload["action"] = "fix";

        _ = Task.Run(async () =>
        {
            var (ok, message) = await SendHipsRequestAsync(payload);
            Ui.Post((() =>
                PostToJs("toast", new { level = ok ? "ok" : "warn", msg = message })));
        });
    }

    private void AllowHips(HipsAlertWatcher.Alert a)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(a.Where) || string.IsNullOrWhiteSpace(a.Rule))
            {
                PostToJs("toast", new { level = "warn", msg = "Nie ma czego dodać do wyjątków — zdarzenie nie wskazuje obiektu." });
                return;
            }

            string path = Path.Combine(_appDataDir, "data", "hips-rules.json");
            JsonObject root;
            try
            {
                root = (File.Exists(path) ? JsonNode.Parse(File.ReadAllText(path)) as JsonObject : null)
                       ?? new JsonObject();
            }
            catch { root = new JsonObject(); }

            if (root["exceptions"] is not JsonObject ex) { ex = new JsonObject(); root["exceptions"] = ex; }
            if (ex[a.Rule] is not JsonArray arr) { arr = new JsonArray(); ex[a.Rule] = arr; }

            foreach (var item in arr)
                if (string.Equals(item?.GetValue<string>(), a.Where, StringComparison.OrdinalIgnoreCase))
                {
                    _hipsAlerts?.Mute(a.Rule, a.Where);
                    return;
                }

            arr.Add(a.Where);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, root.ToJsonString());

            _hipsAlerts?.Mute(a.Rule, a.Where);
            PostToJs("toast", new { level = "ok", msg = $"Dodano do wyjątków: {a.Where}" });
        }
        catch (Exception exx)
        {
            PostToJs("toast", new { level = "warn", msg = $"Nie udało się dodać wyjątku: {exx.Message}" });
        }
    }

    private async Task<(bool ok, string message)> SendHipsRequestAsync(JsonObject payload)
    {
        try
        {
            string dir = Path.Combine(_appDataDir, "data");
            Directory.CreateDirectory(dir);
            string resultPath = Path.Combine(dir, "hips-undo-result.json");
            try { File.Delete(resultPath); } catch { }
            File.WriteAllText(Path.Combine(dir, "hips-undo-request.json"), payload.ToJsonString());

            for (int i = 0; i < 40 && !File.Exists(resultPath); i++)
                await Task.Delay(250);

            if (!File.Exists(resultPath))
                return (false, "Usługa ochrony rezydentnej nie odpowiedziała. Sprawdź, czy jest uruchomiona.");

            var node = JsonNode.Parse(File.ReadAllText(resultPath));
            return (node?["ok"]?.GetValue<bool>() ?? false,
                    node?["message"]?.GetValue<string>() ?? "");
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    private void OpenHipsEvents()
    {
        try
        {
            Shell.Reveal();
            PostToJs("hips.show", new { cat = "events" });
        }
        catch { }
    }
}
