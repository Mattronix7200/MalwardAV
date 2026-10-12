using System.Text;
using Malward.Engine.Util;

namespace Malward.Engine.Heuristic;

public static class ScriptHeuristics
{
    public sealed record Hit(string Detection, ScriptConfidence Confidence, string Reason);

    public enum ScriptConfidence { Medium, High }

    private static readonly HashSet<string> ScriptExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".vbs", ".vbe", ".vb", ".js", ".jse", ".wsf", ".wsh", ".hta",
        ".bat", ".cmd", ".ps1", ".psm1",
    };

    private const int MaxRead = 2 * 1024 * 1024;

    private const int SniffBytes = 4096;

    public static Hit? Check(string path)
    {
        try
        {
            var ext = Path.GetExtension(path);
            bool isScriptExt = ScriptExts.Contains(ext);

            byte[] head;
            long length;
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                length = fs.Length;
                if (length == 0) return null;
                int want = (int)Math.Min(length, isScriptExt ? MaxRead : SniffBytes);
                head = new byte[want];
                int got = fs.Read(head, 0, want);
                if (got <= 0) return null;
                if (got < want) Array.Resize(ref head, got);

                if (!isScriptExt)
                {
                    if (!LooksLikePrependedScript(Decode(head))) return null;

                    fs.Position = 0;
                    int full = (int)Math.Min(length, MaxRead);
                    head = new byte[full];
                    int n = fs.Read(head, 0, full);
                    if (n < full) Array.Resize(ref head, n);
                }
            }

            var text = Decode(head);
            if (text.Length < 40) return null;

            return Judge(text, ext);
        }
        catch { return null; }
    }

    public static Hit? CheckText(string text, string ext = ".vbs") => Judge(text ?? "", ext);

    private static string Decode(byte[] bytes)
    {
        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
            return Encoding.Unicode.GetString(bytes, 2, bytes.Length - 2);
        if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF)
            return Encoding.BigEndianUnicode.GetString(bytes, 2, bytes.Length - 2);
        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
            return Encoding.UTF8.GetString(bytes, 3, bytes.Length - 3);

        int zeros = 0, checkTo = Math.Min(bytes.Length, 512);
        for (int i = 1; i < checkTo; i += 2) if (bytes[i] == 0) zeros++;
        if (checkTo > 8 && zeros > checkTo / 4) return Encoding.Unicode.GetString(bytes);

        return Encoding.UTF8.GetString(bytes);
    }

    private static bool LooksLikePrependedScript(string head)
    {
        var h = head.ToLowerInvariant();
        int marks = 0;
        if (h.Contains("createobject(")) marks++;
        if (h.Contains("wscript.")) marks++;
        if (h.Contains("on error resume next")) marks++;
        if (h.Contains("scripting.filesystemobject")) marks++;
        if (h.Contains("wscript.shell")) marks++;
        if (h.Contains("<script")) marks++;
        return marks >= 2;
    }

    private enum Intent
    {
        Download, Execute, Elevate, Persist, Tamper, Replicate, Infect, Hide, Obfuscate, Enumerate,
    }

    private static bool UsesScriptHost(string t) =>
        Any(t, "activexobject", "wscript.", "wsh.shell", "getobject(", "createobject(",
               "scripting.filesystemobject", "shell.application");

    private static Hit? Judge(string raw, string ext)
    {
        var t = raw.ToLowerInvariant();

        if ((ext.Equals(".js", StringComparison.OrdinalIgnoreCase)
          || ext.Equals(".jse", StringComparison.OrdinalIgnoreCase))
            && !UsesScriptHost(t))
            return null;

        var found = new Dictionary<Intent, string>();

        void Mark(Intent i, string why) { if (!found.ContainsKey(i)) found[i] = Loc.T(why); }

        bool httpObject = Any(t, "microsoft.xmlhttp", "msxml2.xmlhttp", "msxml2.serverxmlhttp",
                                 "winhttp.winhttprequest", "xmlhttprequest")
                       || Any(t, "certutil -urlcache", "bitsadmin /transfer", "invoke-webrequest",
                                 "downloadfile", "downloadstring", "start-bitstransfer");
        bool toDisk = Any(t, "savetofile", "adodb.stream", "downloadfile", "-outfile", "curl -o", "wget ");
        if (httpObject && toDisk) Mark(Intent.Download, "pobiera plik z sieci i zapisuje go na dysku");

        bool shellExecuteCall = t.Contains(".shellexecute") && !t.Contains("useshellexecute");
        bool runsSomething = Any(t, "wscript.shell") && Any(t, ".run", ".exec(")
                          || shellExecuteCall
                          || Any(t, "cmd /c", "cmd.exe /c", "powershell -", "start-process");
        if (runsSomething) Mark(Intent.Execute, "uruchamia zewnętrzny program lub polecenie");

        if (t.Contains("\"runas\"") || t.Contains("'runas'") || t.Contains(", \"runas\"")
            || (t.Contains("runas") && t.Contains("shellexecute")))
            Mark(Intent.Elevate, "podnosi własne uprawnienia do administratora");

        if (Any(t, "currentversion\\run", "currentversion/run", "\\runonce", "schtasks /create",
                   "\\start menu\\programs\\startup", "win.ini", "userinit"))
            Mark(Intent.Persist, "zapewnia sobie uruchamianie po restarcie");

        var tamperKeys = new (string Needle, string Opis)[]
        {
            ("disabletaskmgr",              "blokada Menedżera zadań"),
            ("disableregistrytools",        "blokada Edytora rejestru"),
            ("disablecmd",                  "blokada wiersza poleceń"),
            ("enablelua",                   "wyłączenie kontroli konta użytkownika (UAC)"),
            ("image file execution options","przejęcie uruchamiania programów (IFEO)"),
            ("\\debugger",                  "podstawienie debuggera pod cudzy program"),
            ("safeboot",                    "ingerencja w tryb awaryjny"),
            ("legalnotice",                 "komunikat przed logowaniem"),
            ("restrictrun",                 "ograniczenie listy dozwolonych programów"),
            ("nodrives",                    "ukrycie dysków"),
            ("noviewondrive",               "zablokowanie dostępu do dysków"),
            ("nofolderoptions",             "ukrycie opcji folderów"),
            ("hidefileext",                 "ukrycie rozszerzeń plików"),
            ("nocontrolpanel",              "blokada Panelu sterowania"),
            ("disablelockworkstation",      "blokada blokowania stacji"),
            ("exefile\\shell\\open\\command","przejęcie uruchamiania plików .exe"),
            ("taskkill /f /im explorer",    "wymuszone zamknięcie powłoki systemu"),
            ("takeown /f",                  "przejęcie własności plików systemowych"),
            ("icacls",                      "zmiana uprawnień do plików systemowych"),
            ("assoc .lnk",                  "podmiana skojarzenia skrótów"),
            ("windefend",                   "ingerencja w usługę Windows Defender"),
            ("smartscreen",                 "wyłączanie SmartScreen"),
        };
        var tamperHits = new List<string>();
        foreach (var (needle, opis) in tamperKeys)
            if (t.Contains(needle)) tamperHits.Add(Loc.T(opis));
        if (tamperHits.Count >= 2)
            Mark(Intent.Tamper, Loc.T("wyłącza zabezpieczenia systemu:") + " " + string.Join(", ", tamperHits.Take(5))
                 + (tamperHits.Count > 5 ? $" (+{tamperHits.Count - 5})" : ""));

        bool readsSelf = Any(t, "wscript.scriptfullname", "scriptfullname", "wscript.scriptname")
                      && Any(t, "readall", "opentextfile", "copyfile", "getfile(");
        bool writesScripts = Any(t, "createtextfile") && Any(t, ".vbs\"", ".vbs'", ".js\"", ".vbe\"", ".wsf\"")
                          || t.Contains("copyfile") && Any(t, ".vbs", ".js");
        if (readsSelf && writesScripts)
            Mark(Intent.Replicate, "kopiuje własny kod do innych plików skryptowych (robak)");

        bool infects = Any(t, "opentextfile") && t.Contains("readall")
                    && t.Contains("createtextfile")
                    && Any(t, ".doc", ".xls", ".ppt", ".pdf", ".jpg", ".zip", ".rar", ".dll", ".lnk");
        if (infects) Mark(Intent.Infect, "dopisuje własny kod do istniejących plików użytkownika");

        if (Any(t, ".attributes = 2", ".attributes = 6", ".attributes=2", ".attributes=6",
                   ".attributes = 1", ".attributes=1", "attrib +h", "attrib +s"))
            Mark(Intent.Hide, "ukrywa utworzone pliki lub foldery");
        else if (Any(t, "-windowstyle hidden", "-w hidden", "-windowstyle 1"))
            Mark(Intent.Hide, "uruchamia się bez widocznego okna");

        int chr = Count(t, "chr(");
        bool psZaciemnienie = Any(t, "-encodedcommand", " -enc ")
                           || (t.Contains("frombase64string")
                               && Any(t, "iex", "invoke-expression", ".invoke("));
        if (chr >= 20 || Any(t, "execute(", "eval(unescape", "fromcharcode", "document.write(unescape")
            || psZaciemnienie
            || LongestLine(raw) > 3000)
            Mark(Intent.Obfuscate, "kod jest celowo zaciemniony");

        if (Any(t, ".subfolders") && Any(t, "drivetype", "getdrive", "drives"))
            Mark(Intent.Enumerate, "przechodzi rekurencyjnie po dyskach i folderach");

        if (found.Count == 0) return null;

        string Why(params Intent[] ii) => string.Join("; ", ii.Where(found.ContainsKey).Select(i => found[i]));
        bool Has(params Intent[] ii) => ii.All(found.ContainsKey);

        string family = (ext ?? "").ToLowerInvariant() switch
        {
            ".js" or ".jse"   => "JS",
            ".ps1" or ".psm1" => "PS",
            ".bat" or ".cmd"  => "BAT",
            ".hta"            => "HTA",
            _                 => "VBS",
        };
        bool powerShell = family == "PS";

        if (Has(Intent.Replicate))
            return new Hit($"Worm.{family}.Generic", ScriptConfidence.High,
                Loc.T("Skrypt powiela sam siebie.") + " " + Why(Intent.Replicate, Intent.Enumerate, Intent.Hide, Intent.Persist));

        if (Has(Intent.Infect))
            return new Hit($"Virus.{family}.Infector", ScriptConfidence.High,
                Loc.T("Skrypt infekuje istniejące pliki.") + " " + Why(Intent.Infect, Intent.Hide));

        if (Has(Intent.Download, Intent.Execute))
        {
            bool corroborated = !powerShell
                || found.ContainsKey(Intent.Obfuscate) || found.ContainsKey(Intent.Hide)
                || found.ContainsKey(Intent.Tamper)    || found.ContainsKey(Intent.Persist)
                || found.ContainsKey(Intent.Elevate);
            if (corroborated)
                return new Hit($"Trojan.{family}.Downloader", ScriptConfidence.High,
                    Loc.T("Skrypt pobiera i uruchamia plik z internetu.") + " "
                    + Why(Intent.Download, Intent.Execute, Intent.Obfuscate, Intent.Hide, Intent.Elevate, Intent.Persist));
        }

        if (Has(Intent.Tamper) && (Has(Intent.Persist) || Has(Intent.Elevate) || Has(Intent.Execute)))
            return new Hit($"Trojan.{family}.Sabotage", ScriptConfidence.High,
                Loc.T("Skrypt wyłącza zabezpieczenia systemu.") + " " + Why(Intent.Tamper, Intent.Persist, Intent.Elevate));

        if (found.Count >= 3)
            return new Hit($"Heur.{family}.Suspicious", ScriptConfidence.Medium,
                Loc.T("Skrypt łączy kilka zachowań typowych dla złośliwego kodu:") + " "
                + string.Join("; ", found.Values.Take(4)));

        if (Has(Intent.Obfuscate, Intent.Execute))
            return new Hit($"Heur.{family}.Obfuscated", ScriptConfidence.Medium,
                "Zaciemniony skrypt uruchamiający polecenia. " + Why(Intent.Obfuscate, Intent.Execute));

        return null;
    }

    private static bool Any(string haystack, params string[] needles)
    {
        foreach (var n in needles) if (haystack.Contains(n, StringComparison.Ordinal)) return true;
        return false;
    }

    private static int Count(string haystack, string needle)
    {
        int n = 0, i = 0;
        while ((i = haystack.IndexOf(needle, i, StringComparison.Ordinal)) >= 0) { n++; i += needle.Length; }
        return n;
    }

    private static int LongestLine(string text)
    {
        int best = 0, cur = 0;
        foreach (var c in text)
        {
            if (c == '\n') { if (cur > best) best = cur; cur = 0; }
            else cur++;
        }
        return Math.Max(best, cur);
    }
}
