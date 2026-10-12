using System;
using System.Collections.Generic;
using System.IO;
using Malward.AppGUI.Services;

namespace Malward.AppGUI;

public partial class AppHost
{
    private bool ReportByBalloon(EventCentre.Entry wpis)
    {
        if (!WebMode) return false;
        try
        {
            _balloonEventId = wpis.Id;
            _tray?.NotifyBalloon(wpis.Title,
                string.IsNullOrWhiteSpace(wpis.Path) ? wpis.Detection : $"{wpis.Detection} — {wpis.Path}",
                OpenEventCentre);
        }
        catch (Exception ex) { CrashLog.Write("web-ui", ex, "balloon for a pending event"); }
        return true;
    }

    private string? _balloonEventId;

    private void OpenEventCentre()
    {
        var id = _balloonEventId;

        OpenInBrowser(id);

        if (!string.IsNullOrEmpty(id)) PostToJs("events.open", new { id });
    }

    private bool ReportFirewallToCentre(FirewallPopupForm.Info info, string appPath, string dir, string? svc)
    {
        try
        {
            string program = !string.IsNullOrWhiteSpace(info.AppName)
                ? info.AppName : Path.GetFileName(appPath);
            string cel = $"{info.RemoteAddress}:{info.RemotePort} ({info.Protocol}, " +
                         (dir == "IN" ? Loc.T("przychodzące") : Loc.T("wychodzące")) + ")";

            var akcje = new List<EventCentre.Choice>
            {
                new("block", "Zablokuj połączenie", Primary: true),
                new("allow", "Zezwól na połączenie"),
                new("once",  "Zezwól na 5 minut"),
            };
            var odpowiedzi = new Dictionary<string, Action>
            {
                ["block"] = () =>
                {
                    _fwListener?.Snooze(appPath, dir, TimeSpan.FromMinutes(30));
                    _fwListener?.MarkAppDecided(appPath);
                },
                ["allow"] = () =>
                {
                    FirewallAllowApp(appPath, dir, svc);
                    _fwListener?.MarkAppDecided(appPath);
                },
                ["once"] = () =>
                {
                    FirewallAllowApp(appPath, dir, svc);
                    _fwListener?.Snooze(appPath, dir, TimeSpan.FromMinutes(5));
                },
            };

            var wpis = EventCentre.Ask("firewall", Loc.T("Program chce połączyć się z siecią"),
                                       "Firewall.OutboundAsk", program, appPath, cel, akcje, odpowiedzi);
            return ReportByBalloon(wpis);
        }
        catch (Exception ex) { CrashLog.Write("event-centre", ex, "firewall prompt"); }
        return false;
    }

    private bool ReportShieldToCentre(IReadOnlyList<ResidentIpc.ShieldEvent> zdarzenia)
    {
        if (_residentIpc == null) return false;
        bool dymkiem = false;
        foreach (var e in zdarzenia)
        {
            try
            {
                bool pyta = string.Equals(e.Mode, "ask", StringComparison.OrdinalIgnoreCase);
                string tytul = pyta
                    ? Loc.T("Wykryto zagrożenie — wymagana decyzja")
                    : Loc.T("Zablokowano zagrożenie");
                string? proces = string.IsNullOrWhiteSpace(e.Process) ? null : e.Process;

                if (!pyta)
                {
                    EventCentre.Report("realtime", tytul, e.Detection, proces, e.File,
                                       string.IsNullOrWhiteSpace(e.Action) ? null : e.Action);

                    if (WebMode) dymkiem = true;
                    continue;
                }

                var ipc = _residentIpc;
                var id = e.Id;
                var wpis = EventCentre.Ask("realtime", tytul, e.Detection, proces, e.File, null,
                    new List<EventCentre.Choice>
                    {
                        new("quarantine", "Przenieś do kwarantanny", Primary: true),
                        new("delete",     "Usuń trwale"),
                        new("ignore",     "Zignoruj ten plik"),
                    },
                    new Dictionary<string, Action>
                    {
                        ["quarantine"] = () => ipc.WriteDecision(id, "quarantine"),
                        ["delete"]     = () => ipc.WriteDecision(id, "delete"),
                        ["ignore"]     = () => ipc.WriteDecision(id, "ignore"),
                    });
                if (ReportByBalloon(wpis)) dymkiem = true;
            }
            catch (Exception ex) { CrashLog.Write("event-centre", ex, "real-time detection"); }
        }
        return dymkiem;
    }

    private void ReportFirewallBlockToCentre(string program, string appPath, string cel, string detekcja)
    {
        try
        {
            EventCentre.Report("firewall", Loc.T("Zablokowano połączenie szkodliwego programu"),
                               detekcja, program, appPath, cel);
        }
        catch (Exception ex) { CrashLog.Write("event-centre", ex, "firewall malware alert"); }
    }

    private bool ReportDetectionToCentre(string rodzaj, string tytul,
                                        RichInfoPopupForm.Entry e, bool mozeDecydowac)
    {
        try
        {
            string? szczegoly = e.Items is { Count: > 0 } ? string.Join(" · ", e.Items) : e.Body;
            string? sciezka = e.FullPath ?? e.Path;

            bool jestCoPrzywracac = mozeDecydowac && e.QuarantineIds is { Count: > 0 };
            if (!jestCoPrzywracac)
            {
                EventCentre.Report(rodzaj, tytul, e.Detection, e.Process, sciezka, szczegoly);
                return WebMode;
            }

            var akcje = new List<EventCentre.Choice>
            {
                new("keep",    "Zostaw w kwarantannie", Primary: true),
                new("restore", "Przywróć plik"),
                new("trust",   "Przywróć i nie blokuj ponownie"),
            };
            var odpowiedzi = new Dictionary<string, Action>
            {
                ["keep"] = () => { },
                ["restore"] = () => RestoreBehavioural(e, exclude: false),
                ["trust"]   = () => RestoreBehavioural(e, exclude: true),
            };

            var wpis = EventCentre.Ask(rodzaj, tytul, e.Detection, e.Process, sciezka,
                                       szczegoly, akcje, odpowiedzi);
            return ReportByBalloon(wpis);
        }
        catch (Exception ex) { CrashLog.Write("event-centre", ex, "detection prompt"); }
        return false;
    }
}
