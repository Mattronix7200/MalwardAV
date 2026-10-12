using System.Text.Json.Nodes;
using Malward.Engine.Util;

namespace Malward.ResidentShield.Hips;

public static class HipsRequests
{
    private static string Dir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Malward", "data");

    private static string RequestPath => Path.Combine(Dir, "hips-undo-request.json");
    private static string ResultPath  => Path.Combine(Dir, "hips-undo-result.json");

    public static void Request(JsonObject undoRecord)
    {
        try
        {
            Directory.CreateDirectory(Dir);
            File.WriteAllText(RequestPath, JsonText.Indented(undoRecord));
        }
        catch { }
    }

    public static bool ProcessPending()
    {
        JsonObject? req;
        try
        {
            if (!File.Exists(RequestPath)) return false;
            req = JsonNode.Parse(File.ReadAllText(RequestPath)) as JsonObject;

            try { File.Delete(RequestPath); } catch { }
        }
        catch { return false; }

        if (req == null) return false;

        bool ok = false;
        string message;
        try
        {
            var kind   = req["kind"]?.GetValue<string>() ?? "";
            var doFix  = string.Equals(req["action"]?.GetValue<string>(), "fix", StringComparison.OrdinalIgnoreCase);

            if (doFix && string.Equals(kind, "file", StringComparison.OrdinalIgnoreCase))
            {
                var rule = req["rule"]?.GetValue<string>() ?? "";
                var path = req["path"]?.GetValue<string>() ?? "";
                if (rule.Length == 0 || path.Length == 0)
                {
                    message = Loc.T("Żądanie niekompletne.");
                }
                else
                {
                    ok = HipsFileWatcher.Revert(rule, path);
                    message = ok
                        ? $"Naprawiono: {path}"
                        : Loc.T("Nie udało się wykonać naprawy — szczegóły w dzienniku usługi.");
                }
            }
            else if (!string.Equals(kind, "registry", StringComparison.OrdinalIgnoreCase))
            {
                message = kind switch
                {
                    "file" => Loc.T("Plik przywrócisz z zakładki Kwarantanna."),
                    "wmi"  => Loc.T("Usuniętej subskrypcji WMI nie da się odtworzyć."),
                    _      => Loc.T("Nieznany rodzaj cofnięcia."),
                };
            }
            else
            {
                var loc   = req["loc"]?.GetValue<string>();
                var op    = req["op"]?.GetValue<string>();
                var value = req["value"]?.GetValue<string>();
                var vkind = req["vkind"]?.GetValue<string>();
                if (string.IsNullOrEmpty(loc) || string.IsNullOrEmpty(op))
                {
                    message = Loc.T("Żądanie niekompletne.");
                }
                else
                {
                    ok = HipsRegistryWatcher.ApplyUndo(loc, op, value, vkind);
                    var what = req["where"]?.GetValue<string>() ?? loc;
                    message = ok
                        ? (doFix ? Loc.F("Naprawiono: {0}", what) : Loc.F("Przywrócono stan sprzed naprawy: {0}", what))
                        : (doFix ? Loc.T("Nie udało się wykonać naprawy — szczegóły w dzienniku usługi.")
                                 : Loc.T("Nie udało się cofnąć naprawy — szczegóły w dzienniku usługi."));
                }
            }
        }
        catch (Exception ex) { message = Loc.F("Błąd: {0}", ex.Message); }

        try
        {
            File.WriteAllText(ResultPath, JsonText.Indented(new JsonObject
            {
                ["ts"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                ["ok"] = ok,
                ["message"] = message,
            }));
        }
        catch { }

        var verb = string.Equals(req["action"]?.GetValue<string>(), "fix", StringComparison.OrdinalIgnoreCase)
            ? Loc.T("Żądanie naprawy") : Loc.T("Żądanie cofnięcia naprawy");
        Log.Info("HIPS", $"{verb}: {(ok ? "wykonane" : "odrzucone")} — {message}");
        return true;
    }
}
