using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Malward.Engine.Util;
using Microsoft.Win32;

namespace Malward.Engine.SysRepair;

public sealed class SystemRepairScanner
{
    public sealed record SysRepairItem(
        string  Id,
        string  Name,
        string  Description,
        string  Category,
        bool    Tampered,
        string? Detail,
        bool    CanAutoRepair);

    private sealed record PolicyCheck(
        string Id, string Name, string Description, string Category,
        string SubKey, string ValueName, int BadValue, int? SafeValue,
        bool Hkcu = true, bool Hklm = true);

    private const string PolSystem   = @"Software\Microsoft\Windows\CurrentVersion\Policies\System";
    private const string PolExplorer = @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";
    private const string PolActiveDt = @"Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop";
    private const string ExplAdv     = @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced";
    private const string PolWinSystem= @"Software\Policies\Microsoft\Windows\System";
    private const string FwStandard  = @"System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile";
    private const string FwPublic    = @"System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile";
    private const string DefenderPol = @"Software\Policies\Microsoft\Windows Defender";
    private const string DefenderRtp = @"Software\Policies\Microsoft\Windows Defender\Real-Time Protection";
    private const string WuAuPol     = @"Software\Policies\Microsoft\Windows\WindowsUpdate\AU";
    private const string CmdProcessor = @"Software\Microsoft\Command Processor";

    private static readonly PolicyCheck[] Policies =
    {
        new("taskmgr",       "Menedżer zadań zablokowany",
            "Malware wyłączyło Menedżera zadań (DisableTaskMgr), by uniemożliwić zakończenie swoich procesów.",
            "policy", PolSystem, "DisableTaskMgr", 1, null),
        new("regedit",       "Edytor rejestru zablokowany",
            "Zablokowano regedit.exe (DisableRegistryTools) — typowe dla malware ukrywającego wpisy w rejestrze.",
            "policy", PolSystem, "DisableRegistryTools", 1, null),
        new("cmd",           "Wiersz poleceń zablokowany",
            "Zablokowano cmd.exe (DisableCMD) — utrudnia diagnostykę i usuwanie zagrożenia.",
            "policy", PolWinSystem, "DisableCMD", 1, null),
        new("controlpanel",  "Panel sterowania zablokowany",
            "Ukryto/zablokowano Panel sterowania i Ustawienia (NoControlPanel).",
            "policy", PolExplorer, "NoControlPanel", 1, null),
        new("run",           "Okno Uruchom zablokowane",
            "Zablokowano okno Uruchom (NoRun).",
            "policy", PolExplorer, "NoRun", 1, null),
        new("folderoptions", "Opcje folderów zablokowane",
            "Zablokowano Opcje folderów (NoFolderOptions) — malware ukrywa własne pliki.",
            "policy", PolExplorer, "NoFolderOptions", 1, null),
        new("desktop",       "Pulpit zablokowany",
            "Ukryto ikony pulpitu / zablokowano pulpit (NoDesktop).",
            "policy", PolExplorer, "NoDesktop", 1, null),
        new("nofind",        "Wyszukiwanie zablokowane",
            "Zablokowano funkcję wyszukiwania (NoFind).",
            "policy", PolExplorer, "NoFind", 1, null),

        new("nosecuritytab", "Karta Zabezpieczenia ukryta",
            "Ukryto kartę Zabezpieczenia we właściwościach plików (NoSecurityTab) — bez niej nie sprawdzisz " +
            "ani nie naprawisz uprawnień do zainfekowanego pliku.",
            "policy", PolExplorer, "NoSecurityTab", 1, null),
        new("nofileassoc",   "Zmiana skojarzeń zablokowana",
            "Zablokowano zmianę skojarzeń plików (NoFileAssociate) — po przejęciu rozszerzenia nie da się go oddać.",
            "policy", PolExplorer, "NoFileAssociate", 1, null),
        new("nosavesettings", "Zapisywanie ustawień pulpitu zablokowane",
            "Ustawienia pulpitu i okien nie są zapisywane (NoSaveSettings) — każda naprawa znika po wylogowaniu.",
            "policy", PolExplorer, "NoSaveSettings", 1, null),
        new("nosettaskbar",  "Ustawienia paska zadań zablokowane",
            "Zablokowano właściwości paska zadań (NoSetTaskbar).",
            "policy", PolExplorer, "NoSetTaskbar", 1, null),
        new("notrayitems",   "Zasobnik systemowy ukryty",
            "Ukryto ikony zasobnika (NoTrayItemsDisplay) — znika z niego również ikona ochrony.",
            "policy", PolExplorer, "NoTrayItemsDisplay", 1, null),
        new("notraymenu",    "Menu zasobnika zablokowane",
            "Zablokowano menu podręczne zasobnika (NoTrayContextMenu).",
            "policy", PolExplorer, "NoTrayContextMenu", 1, null),
        new("nopintaskbar",  "Przypinanie do paska zadań zablokowane",
            "Zablokowano przypinanie programów do paska zadań (NoPinningToTaskbar).",
            "policy", PolExplorer, "NoPinningToTaskbar", 1, null),
        new("nopinnedlist",  "Lista przypiętych na pasku ukryta",
            "Ukryto listę przypiętych programów na pasku zadań (TaskbarNoPinnedList).",
            "policy", PolExplorer, "TaskbarNoPinnedList", 1, null),
        new("nostartpinned", "Lista przypiętych w menu Start ukryta",
            "Ukryto przypięte programy w menu Start (NoStartMenuPinnedList).",
            "policy", PolExplorer, "NoStartMenuPinnedList", 1, null),
        new("nostartmfu",    "Lista ostatnio używanych ukryta",
            "Ukryto listę najczęściej używanych programów (NoStartMenuMFUprogramsList).",
            "policy", PolExplorer, "NoStartMenuMFUprogramsList", 1, null),
        new("nostartmore",   "Pozycja Wszystkie programy ukryta",
            "Ukryto listę wszystkich programów w menu Start (NoStartMenuMorePrograms).",
            "policy", PolExplorer, "NoStartMenuMorePrograms", 1, null),
        new("nolockws",      "Blokowanie stacji roboczej wyłączone",
            "Wyłączono blokowanie stacji roboczej (DisableLockWorkstation) — użytkownik nie zablokuje ekranu " +
            "klawiszami Win+L, zostawiając sesję otwartą.",
            "policy", PolSystem, "DisableLockWorkstation", 1, null),
        new("uncCheck",      "Kontrola ścieżek sieciowych wyłączona",
            "Wyłączono sprawdzanie ścieżek UNC w procesorze poleceń (DisableUNCCheck) — pozwala uruchamiać " +
            "polecenia wprost z udziału sieciowego.",
            "policy", CmdProcessor, "DisableUNCCheck", 1, null),
        new("wallpaperlock", "Blokada zmiany tapety",
            "Zablokowano zmianę tapety (NoChangingWallPaper) — malware wymusza własną tapetę (np. żądanie okupu).",
            "policy", PolActiveDt, "NoChangingWallPaper", 1, null),
        new("hidefileext",   "Ukrywanie rozszerzeń plików",
            "Włączono ukrywanie rozszerzeń (HideFileExt) — malware podszywa się pod dokumenty (faktura.pdf.exe).",
            "ui", ExplAdv, "HideFileExt", 1, 0, Hklm: false),
        new("hiddenfiles",   "Ukryte pliki niewidoczne",
            "Ustawiono niewidoczność plików/folderów ukrytych (Hidden=2) — malware ukrywa swoje pliki.",
            "ui", ExplAdv, "Hidden", 2, 1, Hklm: false),

        new("uac_lua",       "Kontrola konta użytkownika (UAC) wyłączona",
            "EnableLUA=0 — malware wyłączyło UAC, aby podnosić uprawnienia bez pytania. Naprawa włącza UAC (wymaga restartu).",
            "security", PolSystem, "EnableLUA", 0, 1, Hkcu: false),
        new("uac_noprompt",  "UAC podnosi uprawnienia bez pytania",
            "ConsentPromptBehaviorAdmin=0 — monit UAC nie pojawia się dla administratora. Naprawa przywraca monit.",
            "security", PolSystem, "ConsentPromptBehaviorAdmin", 0, 5, Hkcu: false),
        new("firewall_std",  "Zapora Windows wyłączona (profil prywatny)",
            "EnableFirewall=0 w profilu standardowym zapory — malware otworzyło ruch. Naprawa włącza zaporę.",
            "security", FwStandard, "EnableFirewall", 0, 1, Hkcu: false),
        new("firewall_pub",  "Zapora Windows wyłączona (profil publiczny)",
            "EnableFirewall=0 w profilu publicznym zapory. Naprawa włącza zaporę.",
            "security", FwPublic, "EnableFirewall", 0, 1, Hkcu: false),
        new("smartscreen",   "SmartScreen wyłączony przez zasady",
            "EnableSmartScreen=0 — wyłączono reputacyjną ochronę przed pobranymi plikami. Naprawa ją włącza.",
            "security", PolWinSystem, "EnableSmartScreen", 0, 1, Hkcu: false),
        new("defender_as",   "Windows Defender wyłączony przez zasady",
            "DisableAntiSpyware=1 — malware wyłączyło Defendera przez zasady. Naprawa usuwa ten wpis.",
            "security", DefenderPol, "DisableAntiSpyware", 1, null, Hkcu: false),
        new("defender_rtp",  "Ochrona w czasie rzeczywistym Defendera wyłączona",
            "DisableRealtimeMonitoring=1 — wyłączono skanowanie w czasie rzeczywistym. Naprawa usuwa ten wpis.",
            "security", DefenderRtp, "DisableRealtimeMonitoring", 1, null, Hkcu: false),
        new("winupdate",     "Windows Update zablokowany przez zasady",
            "NoAutoUpdate=1 — malware zablokowało aktualizacje, by system pozostał podatny. Naprawa usuwa ten wpis.",
            "security", WuAuPol, "NoAutoUpdate", 1, null, Hkcu: false),
        new("wdigest",       "Hasła przechowywane jawnie w pamięci (WDigest)",
            "UseLogonCredential=1 — wymusza trzymanie haseł w postaci jawnej w LSASS (ułatwia kradzież poświadczeń). Naprawa usuwa wpis.",
            "security", @"System\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", 1, null, Hkcu: false),
    };

    private static string[]? _ifeoWatched;
    private static string[] IfeoWatched =>
        _ifeoWatched ??= Data.SignatureStore.List("security_binaries");

    public List<SysRepairItem> Scan(ISet<string>? enabled = null)
    {
        var results = new List<SysRepairItem>();

        foreach (var p in Policies)
        {
            if (enabled != null && !enabled.Contains(p.Id)) continue;
            var (bad, detail) = CheckPolicy(p);
            results.Add(new SysRepairItem(p.Id, p.Name, p.Description, p.Category, bad, detail, CanAutoRepair: true));
        }

        if (enabled == null || enabled.Contains("ifeo"))
        {
            var (bad, detail) = CheckIfeo();
            results.Add(new SysRepairItem("ifeo", "Przejęcie uruchamiania programów (IFEO)",
                "Wpis w Image File Execution Options przejmuje start wskazanego programu: Debugger uruchamia " +
                "malware zamiast niego, VerifierDlls wstrzykuje bibliotekę przy ładowaniu obrazu, a MonitorProcess " +
                "(SilentProcessExit) startuje program dokładnie wtedy, gdy cel zostanie zabity. Tak wyłącza się " +
                "antywirusa (np. Debugger na MpCmdRun.exe blokuje skanowanie Defendera) i Menedżera zadań. " +
                "Sprawdzane w obu widokach rejestru — 64- i 32-bitowym (WOW6432Node).",
                "hijack", bad, detail, CanAutoRepair: true));
        }
        if (enabled == null || enabled.Contains("exehijack"))
        {
            var (bad, detail) = CheckExeAssoc();
            results.Add(new SysRepairItem("exehijack", "Zablokowane uruchamianie plików EXE",
                "Zmieniono skojarzenie plików .exe (exefile\\shell\\open\\command) — może uniemożliwić " +
                "uruchomienie JAKICHKOLWIEK programów (atak destrukcyjny) lub przekierować je do malware.",
                "hijack", bad, detail, CanAutoRepair: true));
        }
        if (enabled == null || enabled.Contains("winlogonshell"))
        {
            var (bad, detail) = CheckWinlogonShell();
            results.Add(new SysRepairItem("winlogonshell", "Podmieniona powłoka systemu (Winlogon)",
                "Wartość Winlogon\\Shell powinna wskazywać explorer.exe. Podmiana = malware uruchamiane " +
                "zamiast pulpitu przy każdym logowaniu.",
                "hijack", bad, detail, CanAutoRepair: true));
        }
        if (enabled == null || enabled.Contains("hiddendrives"))
        {
            var (bad, detail) = CheckHiddenDrives();
            results.Add(new SysRepairItem("hiddendrives", "Ukryte dyski w Eksploratorze",
                "Malware (często typu Joke) ustawia politykę NoDrives/NoViewOnDrive, aby ukryć dysk C: " +
                "lub inne dyski w Eksploratorze i uniemożliwić do nich dostęp. Naprawa przywraca widoczność.",
                "ui", bad, detail, CanAutoRepair: true));
        }
        if (enabled == null || enabled.Contains("restrictrun"))
        {
            var (bad, detail) = CheckRestrictRun();
            results.Add(new SysRepairItem("restrictrun", "Dozwolone tylko wybrane programy (RestrictRun)",
                "Polityka RestrictRun pozwala uruchamiać WYŁĄCZNIE programy wymienione na liście — wszystko " +
                "poza nią przestaje działać, razem z narzędziami do usunięcia infekcji. Na czystym Windowsie " +
                "ta polityka nie jest ustawiona. Naprawa usuwa ją wraz z listą.",
                "policy", bad, detail, CanAutoRepair: true));
        }
        if (enabled == null || enabled.Contains("safeboot"))
        {
            var (bad, detail) = CheckSafeBoot();
            results.Add(new SysRepairItem("safeboot", "Uszkodzony tryb awaryjny",
                "Klucze SafeBoot\\Minimal i SafeBoot\\Network opisują, co ma się uruchomić w trybie awaryjnym. " +
                "Ich skasowanie odbiera ostatnią drogę ratunku — system przestaje wstawać w trybie awaryjnym. " +
                "Sprawdzana jest też AlternateShell, którą malware podmienia, by w trybie awaryjnym uruchomić siebie.",
                "boot", bad, detail, CanAutoRepair: true));
        }
        if (enabled == null || enabled.Contains("legalnotice"))
        {
            var (bad, detail) = CheckLegalNotice();
            results.Add(new SysRepairItem("legalnotice", "Komunikat wyświetlany przed logowaniem",
                "legalnoticecaption i legalnoticetext wstawiają okno, które trzeba zatwierdzić przed każdym " +
                "logowaniem. Bywa używane zgodnie z przeznaczeniem w firmach, dlatego pozycja zgłasza tylko " +
                "treść wskazującą na infekcję. Naprawa usuwa oba wpisy.",
                "ui", bad, detail, CanAutoRepair: true));
        }
        if (enabled == null || enabled.Contains("assochijack"))
        {
            var (bad, detail) = CheckAssocHijack();
            results.Add(new SysRepairItem("assochijack", "Przejęte skojarzenia typów plików",
                "Poza .exe malware przejmuje polecenia dla innych typów: regfile (import .reg), vbsfile i jsfile " +
                "(skrypty), inffile (instalacja), htafile. Każde z nich zabiera jedno z narzędzi, którym " +
                "próbowałbyś to naprawić. Naprawa przywraca polecenia systemowe.",
                "hijack", bad, detail, CanAutoRepair: true));
        }
        if (enabled == null || enabled.Contains("mbr"))
        {
            var (bad, detail) = CheckMbr();
            results.Add(new SysRepairItem("mbr", "Rekord rozruchowy / bootloader dysku (MBR/GPT)",
                "Sprawdza rozruch dysku 0: sygnaturę 0x55AA oraz — na dyskach UEFI/GPT — nagłówek \"EFI PART\" (LBA1). " +
                "Ich uszkodzenie oznacza wymazany bootloader lub nadpisaną tablicę partycji (wiper/bootkit, np. Ana.exe). " +
                "Naprawa wymaga środowiska odzyskiwania (bootrec /fixmbr /fixboot lub odtworzenie GPT).",
                "boot", bad, detail, CanAutoRepair: false));
        }
        if (enabled == null || enabled.Contains("wallpaper"))
        {
            var (bad, detail) = CheckWallpaper();
            results.Add(new SysRepairItem("wallpaper", "Tapeta pulpitu zmieniona / usunięta",
                "Porównuje tapetę z kopią zapisaną w poprzedniej sesji. Ransomware podmienia tapetę na żądanie " +
                "okupu albo ją usuwa. Malward trzyma kopię tapety i potrafi ją przywrócić.",
                "ui", bad, detail, CanAutoRepair: true));
        }
        if (enabled == null || enabled.Contains("cursor"))
        {
            var (bad, detail) = CheckCursor();
            results.Add(new SysRepairItem("cursor", "Podmieniony wskaźnik myszy (kursor)",
                "Wykrywa kursory wskazujące pliki .ani/.cur w podejrzanych lokalizacjach (Temp/AppData) — " +
                "typowe dla malware typu joke. Naprawa przywraca domyślny schemat kursorów.",
                "ui", bad, detail, CanAutoRepair: true));
        }
        if (enabled == null || enabled.Contains("fileicons"))
        {
            var (bad, detail) = CheckFileIcons();
            results.Add(new SysRepairItem("fileicons", "Podmienione ikony plików",
                "Sprawdza ikonę plików EXE/skrótów oraz nadpisania w „Shell Icons”. Malware podmienia ikony, " +
                "by ukryć się pod znajomym wyglądem. Naprawa przywraca domyślne ikony.",
                "ui", bad, detail, CanAutoRepair: true));
        }
        if (enabled == null || enabled.Contains("uacbypass"))
        {
            var (bad, detail) = CheckUacBypass();
            results.Add(new SysRepairItem("uacbypass", "Obejście UAC przez przejęcie skojarzenia (COM/protokół)",
                "Klasyczne obejścia UAC podkładają własną komendę pod skojarzenie, które zaufany proces Windows " +
                "otwiera z podniesionymi uprawnieniami bez monitu. Obecność takiego wpisu w " +
                "HKCU\\Software\\Classes to niemal zawsze atak; której techniki dotyczy, pokazuje kolumna szczegółów. " +
                "Naprawa usuwa podłożone klucze.",
                "hijack", bad, detail, CanAutoRepair: true));
        }
        if (enabled == null || enabled.Contains("autologon"))
        {
            var (bad, detail) = CheckAutoLogon();
            results.Add(new SysRepairItem("autologon", "Automatyczne logowanie z hasłem w rejestrze",
                "AutoAdminLogon=1 z DefaultPassword zapisanym jawnie w Winlogon — logowanie bez hasła i hasło widoczne " +
                "dla każdego procesu. Naprawa wyłącza autologowanie i usuwa zapisane hasło.",
                "security", bad, detail, CanAutoRepair: true));
        }

        for (int i = 0; i < results.Count; i++)
        {
            var r = results[i];
            results[i] = r with
            {
                Name        = Loc.T(r.Name),
                Description = Loc.T(r.Description),
                Detail      = r.Detail == null ? null : Loc.T(r.Detail),
            };
        }

        return results;
    }

    public (bool ok, string? error) Repair(string id)
    {
        try
        {
            var pol = Array.Find(Policies, p => p.Id == id);
            if (pol != null) return RepairPolicy(pol);

            return id switch
            {
                "ifeo"          => RepairIfeo(),
                "restrictrun"   => RepairRestrictRun(),
                "safeboot"      => RepairSafeBoot(),
                "legalnotice"   => RepairLegalNotice(),
                "assochijack"   => RepairAssocHijack(),
                "exehijack"     => RepairExeAssoc(),
                "winlogonshell" => RepairWinlogonShell(),
                "hiddendrives"  => RepairHiddenDrives(),
                "wallpaper"     => RepairWallpaper(),
                "cursor"        => RepairCursor(),
                "fileicons"     => RepairFileIcons(),
                "uacbypass"     => RepairUacBypass(),
                "autologon"     => RepairAutoLogon(),
                "mbr"           => (false, "Naprawa MBR nie jest możliwa z działającego systemu — uruchom bootrec /fixmbr w środowisku odzyskiwania Windows."),
                _               => (false, $"Nieznana pozycja: {id}"),
            };
        }
        catch (UnauthorizedAccessException)
        {
            return (false, "Brak uprawnień administratora do naprawy tej pozycji.");
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    private const string PolExplorerRestrict =
        @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";

    private static (bool bad, string? detail) CheckRestrictRun()
    {
        var hits = new List<string>();
        foreach (var (root, label) in new[] { (Registry.CurrentUser, "HKCU"), (Registry.LocalMachine, "HKLM") })
        {
            if (ReadInt(root, PolExplorerRestrict, "RestrictRun") != 1) continue;
            int allowed = 0;
            try
            {
                using var list = root.OpenSubKey(PolExplorerRestrict + @"\RestrictRun");
                allowed = list?.GetValueNames().Length ?? 0;
            }
            catch { }
            hits.Add($"{label} (dozwolonych programów: {allowed})");
        }
        return hits.Count > 0 ? (true, "RestrictRun=1 w " + string.Join(", ", hits)) : (false, null);
    }

    private static (bool ok, string? error) RepairRestrictRun()
    {
        foreach (var root in new[] { Registry.CurrentUser, Registry.LocalMachine })
        {
            try
            {
                using var k = root.OpenSubKey(PolExplorerRestrict, writable: true);
                if (k == null) continue;
                k.DeleteValue("RestrictRun", throwOnMissingValue: false);

                try { k.DeleteSubKeyTree("RestrictRun", throwOnMissingSubKey: false); } catch { }
            }
            catch (UnauthorizedAccessException) {  }
        }
        return (true, null);
    }

    private const string SafeBootKey = @"System\CurrentControlSet\Control\SafeBoot";

    private static (bool bad, string? detail) CheckSafeBoot()
    {
        var problems = new List<string>();
        foreach (var set in new[] { "Minimal", "Network" })
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey($@"{SafeBootKey}\{set}");
                if (k == null) { problems.Add($"brak klucza SafeBoot\\{set}"); continue; }

                if (k.SubKeyCount == 0) problems.Add($"SafeBoot\\{set} jest pusty");
            }
            catch {  }
        }
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(SafeBootKey);
            var shell = k?.GetValue("AlternateShell") as string;
            if (!string.IsNullOrWhiteSpace(shell)
                && !shell.Trim().Equals("cmd.exe", StringComparison.OrdinalIgnoreCase))
                problems.Add($"AlternateShell = {shell}");
        }
        catch { }
        return problems.Count > 0 ? (true, string.Join("; ", problems)) : (false, null);
    }

    private static (bool ok, string? error) RepairSafeBoot()
    {
        string? note = null;
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(SafeBootKey, writable: true);
            if (k != null)
            {
                var shell = k.GetValue("AlternateShell") as string;
                if (!string.IsNullOrWhiteSpace(shell)
                    && !shell.Trim().Equals("cmd.exe", StringComparison.OrdinalIgnoreCase))
                    k.SetValue("AlternateShell", "cmd.exe", RegistryValueKind.String);
            }
        }
        catch (UnauthorizedAccessException) { return (false, "Brak uprawnień administratora."); }
        catch (Exception ex) { return (false, ex.Message); }

        foreach (var set in new[] { "Minimal", "Network" })
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey($@"{SafeBootKey}\{set}");
                if (k == null || k.SubKeyCount == 0)
                    note = "Przywrócono AlternateShell, ale listy trybu awaryjnego (SafeBoot\\Minimal / \\Network) "
                         + "nie da się odtworzyć z niczego — trzeba je przywrócić z punktu przywracania systemu "
                         + "albo z kopii rejestru innego komputera z tą samą wersją Windows.";
            }
            catch { }
        }
        return note == null ? (true, null) : (false, note);
    }

    private static readonly string[] BannerWords =
        { "hack", "wreck", "virus", "pwn", "owned", "ransom", "bitcoin", "your pc has been",
          "twoj komputer", "zostal zainfekowany", "zaplac" };

    private static (bool bad, string? detail) CheckLegalNotice()
    {
        foreach (var (root, label) in new[] { (Registry.LocalMachine, "HKLM"), (Registry.CurrentUser, "HKCU") })
        {
            try
            {
                using var k = root.OpenSubKey(PolSystem);
                var cap = (k?.GetValue("legalnoticecaption") as string ?? "").Trim();
                var txt = (k?.GetValue("legalnoticetext") as string ?? "").Trim();
                if (cap.Length == 0 && txt.Length == 0) continue;
                var joined = (cap + " " + txt).ToLowerInvariant();
                if (BannerWords.Any(w => joined.Contains(w)))
                    return (true, $"{label}: \"{Trim80(cap)}\" / \"{Trim80(txt)}\"");
            }
            catch { }
        }
        return (false, null);
    }

    private static (bool ok, string? error) RepairLegalNotice()
    {
        foreach (var root in new[] { Registry.LocalMachine, Registry.CurrentUser })
        {
            try
            {
                using var k = root.OpenSubKey(PolSystem, writable: true);
                if (k == null) continue;
                k.DeleteValue("legalnoticecaption", throwOnMissingValue: false);
                k.DeleteValue("legalnoticetext", throwOnMissingValue: false);
            }
            catch (UnauthorizedAccessException) { }
        }
        return (true, null);
    }

    private static string Trim80(string s) => s.Length <= 80 ? s : s[..77] + "...";

    private sealed record AssocCheck(string Type, string Verb, string Expected, string Opis);

    private static readonly AssocCheck[] Assocs =
    {
        new("regfile",  "open",    "regedit.exe",  "import plików .reg"),
        new("vbsfile",  "open",    "wscript.exe",  "uruchamianie skryptów VBS"),
        new("vbsfile",  "edit",    "notepad",      "edycja skryptów VBS"),
        new("jsfile",   "open",    "wscript.exe",  "uruchamianie skryptów JS"),
        new("inffile",  "install", "setupapi",     "instalacja plików .inf"),
        new("htafile",  "open",    "mshta.exe",    "uruchamianie plików HTA"),
        new("batfile",  "open",    "%1",           "uruchamianie plików .bat"),
        new("cmdfile",  "open",    "%1",           "uruchamianie plików .cmd"),
        new("scrfile",  "open",    "%1",           "uruchamianie wygaszaczy"),
        new("piffile",  "open",    "%1",           "uruchamianie plików .pif"),
    };

    private static readonly Dictionary<string, string> AssocFix = new(StringComparer.OrdinalIgnoreCase)
    {
        ["regfile|open"]   = "regedit.exe \"%1\"",
        ["vbsfile|open"]   = "%SystemRoot%\\System32\\WScript.exe \"%1\" %*",
        ["vbsfile|edit"]   = "%SystemRoot%\\System32\\Notepad.exe %1",
        ["jsfile|open"]    = "%SystemRoot%\\System32\\WScript.exe \"%1\" %*",
        ["inffile|install"]= "%SystemRoot%\\System32\\InfDefaultInstall.exe \"%1\"",
        ["htafile|open"]   = "%SystemRoot%\\System32\\mshta.exe \"%1\" {1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}%U{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5} %*",
        ["batfile|open"]   = "\"%1\" %*",
        ["cmdfile|open"]   = "\"%1\" %*",
        ["scrfile|open"]   = "\"%1\" /S",
        ["piffile|open"]   = "\"%1\" %*",
    };

    private static (bool bad, string? detail) CheckAssocHijack()
    {
        var hits = new List<string>();
        foreach (var a in Assocs)
        {
            var cmd = ReadAssoc(a.Type, a.Verb);
            if (cmd == null) continue;
            if (cmd.Contains(a.Expected, StringComparison.OrdinalIgnoreCase)) continue;
            hits.Add($"{a.Type}\\{a.Verb} -> {Trim80(cmd)}");
        }
        return hits.Count > 0
            ? (true, string.Join("; ", hits.Take(4)) + (hits.Count > 4 ? $" (+{hits.Count - 4})" : ""))
            : (false, null);
    }

    private static string? ReadAssoc(string type, string verb)
    {
        foreach (var root in new[] { Registry.CurrentUser, Registry.LocalMachine })
        {
            try
            {
                using var k = root.OpenSubKey($@"Software\Classes\{type}\shell\{verb}\command");
                var v = k?.GetValue("") as string;
                if (!string.IsNullOrWhiteSpace(v)) return v;
            }
            catch { }
        }
        return null;
    }

    private static (bool ok, string? error) RepairAssocHijack()
    {
        var failed = new List<string>();
        foreach (var a in Assocs)
        {
            var cmd = ReadAssoc(a.Type, a.Verb);
            if (cmd == null || cmd.Contains(a.Expected, StringComparison.OrdinalIgnoreCase)) continue;
            if (!AssocFix.TryGetValue($"{a.Type}|{a.Verb}", out var good)) continue;

            try
            {
                using var hk = Registry.CurrentUser.OpenSubKey(
                    $@"Software\Classes\{a.Type}\shell\{a.Verb}", writable: true);
                hk?.DeleteSubKeyTree("command", throwOnMissingSubKey: false);
            }
            catch { }

            try
            {
                using var k = Registry.LocalMachine.CreateSubKey(
                    $@"Software\Classes\{a.Type}\shell\{a.Verb}\command", writable: true);
                if (k == null) { failed.Add(a.Type); continue; }
                k.SetValue("", good, good.Contains('%') ? RegistryValueKind.ExpandString : RegistryValueKind.String);
            }
            catch (UnauthorizedAccessException) { failed.Add(a.Type + " (brak uprawnień)"); }
            catch (Exception ex) { failed.Add($"{a.Type} ({ex.Message})"); }
        }
        return failed.Count == 0
            ? (true, null)
            : (false, "Nie przywrócono: " + string.Join(", ", failed));
    }

    private static (bool bad, string? detail) CheckPolicy(PolicyCheck p)
    {
        var hits = new List<string>();
        if (p.Hkcu && ReadInt(Registry.CurrentUser, p.SubKey, p.ValueName) == p.BadValue) hits.Add("HKCU");
        if (p.Hklm && ReadInt(Registry.LocalMachine, p.SubKey, p.ValueName) == p.BadValue) hits.Add("HKLM");
        return hits.Count > 0
            ? (true, $"{p.ValueName}={p.BadValue} w {string.Join(", ", hits)}")
            : (false, null);
    }

    private static (bool ok, string? error) RepairPolicy(PolicyCheck p)
    {
        void Fix(RegistryKey root)
        {
            using var k = root.OpenSubKey(p.SubKey, writable: true);
            if (k == null) return;
            if (k.GetValue(p.ValueName) == null) return;
            if (p.SafeValue.HasValue) k.SetValue(p.ValueName, p.SafeValue.Value, RegistryValueKind.DWord);
            else k.DeleteValue(p.ValueName, throwOnMissingValue: false);
        }
        if (p.Hkcu) Fix(Registry.CurrentUser);
        if (p.Hklm) Fix(Registry.LocalMachine);
        return (true, null);
    }

    private const string IfeoKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    private const string SilentExitKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";

    private static readonly RegistryView[] IfeoViews = Environment.Is64BitOperatingSystem
        ? new[] { RegistryView.Registry64, RegistryView.Registry32 }
        : new[] { RegistryView.Default };

    private static string ViewLabel(RegistryView v) => v == RegistryView.Registry32 ? "32-bit" : "64-bit";

    private static readonly HashSet<string> IfeoUnreadableExpected =
        new(StringComparer.OrdinalIgnoreCase) { "DefenderAgentScan.exe", "MpCopyAccelerator.exe" };

    private static void ForEachIfeoImage(bool writable, Action<RegistryView, string, RegistryKey> visit,
                                         Action<RegistryView, string>? unreadable = null)
    {
        foreach (var view in IfeoViews)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);

                using var ifeo = baseKey.OpenSubKey(IfeoKey, writable: false);
                if (ifeo == null) continue;
                foreach (var name in ifeo.GetSubKeyNames())
                {
                    RegistryKey? sub = null;
                    try { sub = ifeo.OpenSubKey(name, writable); }
                    catch { unreadable?.Invoke(view, name); continue; }
                    if (sub == null) continue;
                    using (sub) visit(view, name, sub);
                }
            }
            catch { }
        }
    }

    private static (bool bad, string? detail) CheckIfeo()
    {
        var hits = new List<string>();

        ForEachIfeoImage(writable: false, (view, name, sub) =>
        {
            if (sub.GetValue("Debugger") is string dbg && !string.IsNullOrWhiteSpace(dbg)
                && IsIfeoHijack(dbg))
                hits.Add($"[{ViewLabel(view)}] {name}|Debugger = {dbg}{SecurityToolNote(name)}");

            if (sub.GetValue("VerifierDlls") is string vd && !string.IsNullOrWhiteSpace(vd)
                && !IsSystemVerifierDll(vd))
                hits.Add($"[{ViewLabel(view)}] {name}|VerifierDlls = {vd}{SecurityToolNote(name)}");
        },
        unreadable: (view, name) =>
        {
            if (Util.AdminCheck.IsAdmin() && !IfeoUnreadableExpected.Contains(name))
                hits.Add($"[{ViewLabel(view)}] {name} — brak dostępu do odczytu klucza, zawartości nie da się sprawdzić");
        });

        hits.AddRange(SilentProcessExitHits());
        return hits.Count > 0 ? (true, string.Join("; ", hits)) : (false, null);
    }

    private static bool IsIfeoHijack(string debugger)
    {
        var d = debugger.ToLowerInvariant();
        return !Array.Exists(KnownDebuggers, k => d.Contains(k));
    }

    private static readonly string[] KnownDebuggers =
        { "vsjitdebugger", "windbg", "drwtsn32", "cdb.exe", "ntsd.exe", "vsdebugconsole" };

    private static bool IsSystemVerifierDll(string value)
    {
        foreach (var part in value.Split(new[] { ' ', ';', ',' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var f = Path.GetFileName(part).ToLowerInvariant();
            if (f.StartsWith("vf", StringComparison.Ordinal)) continue;
            if (f is "vrfcore.dll" or "verifier.dll") continue;
            return false;
        }
        return true;
    }

    private static string SecurityToolNote(string imageName) =>
        Array.Exists(IfeoWatched, w => w.Equals(imageName, StringComparison.OrdinalIgnoreCase))
            ? "  ← przejęte narzędzie zabezpieczeń/systemowe"
            : "";

    private static List<string> SilentProcessExitHits()
    {
        var hits = new List<string>();
        foreach (var view in IfeoViews)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                using var root = baseKey.OpenSubKey(SilentExitKey);
                if (root == null) continue;
                foreach (var name in root.GetSubKeyNames())
                {
                    using var sub = root.OpenSubKey(name);
                    if (sub?.GetValue("MonitorProcess") is not string mp || string.IsNullOrWhiteSpace(mp))
                        continue;
                    hits.Add($"[{ViewLabel(view)}] SilentProcessExit {name}|MonitorProcess = {mp}{SecurityToolNote(name)}");
                }
            }
            catch { }
        }
        return hits;
    }

    private static (bool ok, string? error) RepairIfeo()
    {
        var failures = new List<string>();
        int removed = 0;

        foreach (var view in IfeoViews)
        {
            foreach (var (root, isIfeo) in new[] { (IfeoKey, true), (SilentExitKey, false) })
            {
                RegistryKey? baseKey = null, parent = null;
                try
                {
                    baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);

                    parent = baseKey.OpenSubKey(root, writable: false);
                    if (parent == null) continue;

                    foreach (var name in parent.GetSubKeyNames())
                    {
                        var wanted = new List<string>();
                        try
                        {
                            using var ro = parent.OpenSubKey(name, writable: false);
                            if (ro == null) continue;
                            if (isIfeo)
                            {
                                if (ro.GetValue("Debugger") is string d && !string.IsNullOrWhiteSpace(d) && IsIfeoHijack(d))
                                    wanted.Add("Debugger");
                                if (ro.GetValue("VerifierDlls") is string v && !string.IsNullOrWhiteSpace(v) && !IsSystemVerifierDll(v))
                                { wanted.Add("VerifierDlls"); wanted.Add("GlobalFlag"); }
                            }
                            else if (ro.GetValue("MonitorProcess") is string mp && !string.IsNullOrWhiteSpace(mp))
                                wanted.Add("MonitorProcess");
                        }
                        catch
                        {
                            continue;
                        }
                        if (wanted.Count == 0) continue;

                        RegistryKey? rw = null;
                        string? err = null;
                        foreach (var attempt in new Func<RegistryKey?>[]
                        {
                            () => parent.OpenSubKey(name, writable: true),
                            () => parent.OpenSubKey(name, RegistryKeyPermissionCheck.ReadWriteSubTree,
                                                    System.Security.AccessControl.RegistryRights.SetValue
                                                    | System.Security.AccessControl.RegistryRights.QueryValues),
                        })
                        {
                            try { rw = attempt(); if (rw != null) break; }
                            catch (Exception ex) { err ??= ex.Message; }
                        }

                        if (rw == null)
                        {
                            failures.Add($"{ViewLabel(view)} {name} ({string.Join(", ", wanted.Where(w => w != "GlobalFlag"))}) — {err ?? "brak dostępu"}");
                            continue;
                        }
                        using (rw)
                        {
                            foreach (var val in wanted)
                            {
                                try { rw.DeleteValue(val, throwOnMissingValue: false); }
                                catch (Exception ex) { failures.Add($"{ViewLabel(view)} {name}|{val} — {ex.Message}"); }
                            }
                            removed++;
                        }
                    }
                }
                catch (Exception ex) { failures.Add($"{ViewLabel(view)} {root} — {ex.Message}"); }
                finally { parent?.Dispose(); baseKey?.Dispose(); }
            }
        }

        if (failures.Count == 0) return (true, null);
        return (false, $"Usunięto {removed}, nie udało się usunąć {failures.Count}: {string.Join("; ", failures)}");
    }

    private const string ExeCmdKey = @"exefile\shell\open\command";
    private const string ExeCmdGood = "\"%1\" %*";

    private static (bool bad, string? detail) CheckExeAssoc()
    {
        try
        {
            using var k = Registry.ClassesRoot.OpenSubKey(ExeCmdKey);
            var val = k?.GetValue(null) as string;
            if (string.IsNullOrEmpty(val)) return (false, null);
            if (!string.Equals(val.Trim(), ExeCmdGood, StringComparison.OrdinalIgnoreCase))
                return (true, $"exefile open = {val}");
        }
        catch { }
        return (false, null);
    }

    private static (bool ok, string? error) RepairExeAssoc()
    {
        using var k = Registry.ClassesRoot.OpenSubKey(ExeCmdKey, writable: true);
        if (k == null) return (false, "Brak klucza exefile\\shell\\open\\command.");
        k.SetValue(null, ExeCmdGood, RegistryValueKind.ExpandString);
        return (true, null);
    }

    private const string WinlogonKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

    private static (bool bad, string? detail) CheckWinlogonShell()
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(WinlogonKey);
            var shell = k?.GetValue("Shell") as string;
            if (string.IsNullOrEmpty(shell)) return (false, null);
            if (!shell.Trim().Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
                return (true, $"Winlogon Shell = {shell}");
        }
        catch { }
        return (false, null);
    }

    private static (bool ok, string? error) RepairWinlogonShell()
    {
        using var k = Registry.LocalMachine.OpenSubKey(WinlogonKey, writable: true);
        if (k == null) return (false, "Brak klucza Winlogon.");
        k.SetValue("Shell", "explorer.exe", RegistryValueKind.String);
        return (true, null);
    }

    private static (bool bad, string? detail) CheckHiddenDrives()
    {
        var hits = new List<string>();
        foreach (var (root, tag) in new[] { (Registry.CurrentUser, "HKCU"), (Registry.LocalMachine, "HKLM") })
        {
            int? nd = ReadInt(root, PolExplorer, "NoDrives");
            int? nv = ReadInt(root, PolExplorer, "NoViewOnDrive");
            if (nd is > 0) hits.Add($"NoDrives=0x{nd:X} ({DrivesFromMask(nd.Value)}) w {tag}");
            if (nv is > 0) hits.Add($"NoViewOnDrive=0x{nv:X} w {tag}");
        }
        return hits.Count > 0 ? (true, string.Join("; ", hits)) : (false, null);
    }

    private static string DrivesFromMask(int mask)
    {
        var s = new List<string>();
        for (int i = 0; i < 26; i++) if ((mask & (1 << i)) != 0) s.Add($"{(char)('A' + i)}:");
        return s.Count > 0 ? string.Join(" ", s) : "—";
    }

    private static (bool ok, string? error) RepairHiddenDrives()
    {
        foreach (var root in new[] { Registry.CurrentUser, Registry.LocalMachine })
        {
            using var k = root.OpenSubKey(PolExplorer, writable: true);
            if (k == null) continue;
            k.DeleteValue("NoDrives", throwOnMissingValue: false);
            k.DeleteValue("NoViewOnDrive", throwOnMissingValue: false);
        }
        return (true, null);
    }

    private static readonly string GuardDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data", "sysrepair");

    private const string DesktopKey    = @"Control Panel\Desktop";
    private const string CursorsKey    = @"Control Panel\Cursors";
    private const string ShellIconsKey = @"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons";

    private static readonly string[] CursorNames =
    {
        "Arrow", "Help", "AppStarting", "Wait", "Crosshair", "IBeam", "NWPen", "No",
        "SizeNS", "SizeWE", "SizeNWSE", "SizeNESW", "SizeAll", "UpArrow", "Hand", "Pin", "Person",
    };

    private static bool IsSuspiciousLocation(string? path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        var p = path.ToLowerInvariant();
        return p.Contains(@"\temp\") || p.Contains(@"\downloads\") || p.Contains(@"\public\")
            || p.Contains(@"\appdata\local\temp\") || p.Contains(@"\windows\temp\");
    }

    private static string? Sha256OfFile(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            using var sha = SHA256.Create();
            return Convert.ToHexString(sha.ComputeHash(fs));
        }
        catch { return null; }
    }

    private static (bool bad, string? detail) CheckWallpaper()
    {
        try
        {
            Directory.CreateDirectory(GuardDir);
            using var k = Registry.CurrentUser.OpenSubKey(DesktopKey);
            string cur = (k?.GetValue("Wallpaper") as string ?? "").Trim();
            string baselineFile = Path.Combine(GuardDir, "wallpaper.baseline");

            if (!File.Exists(baselineFile))
            {
                if (cur.Length > 0 && File.Exists(cur)) SaveWallpaperBaseline(cur);
                return (false, null);
            }

            var parts = File.ReadAllText(baselineFile).Split('|');
            string basePath = parts.Length > 0 ? parts[0] : "";
            string baseHash = parts.Length > 1 ? parts[1] : "";

            if (cur.Length == 0 || !File.Exists(cur))
                return (true, "Tapeta usunięta lub jej plik nie istnieje — możliwy atak (ransomware/wiper).");

            string curHash = Sha256OfFile(cur) ?? "";
            if (string.Equals(cur, basePath, StringComparison.OrdinalIgnoreCase) && curHash == baseHash)
                return (false, null);

            if (IsSuspiciousLocation(cur))
                return (true, $"Tapeta zmieniona na plik z podejrzanej lokalizacji: {cur}");

            SaveWallpaperBaseline(cur);
            return (false, null);
        }
        catch { return (false, null); }
    }

    private static void SaveWallpaperBaseline(string cur)
    {
        try
        {
            Directory.CreateDirectory(GuardDir);
            string ext = Path.GetExtension(cur);
            if (string.IsNullOrEmpty(ext)) ext = ".img";
            string bakName = "wallpaper-backup" + ext;
            File.Copy(cur, Path.Combine(GuardDir, bakName), overwrite: true);
            File.WriteAllText(Path.Combine(GuardDir, "wallpaper.baseline"),
                cur + "|" + (Sha256OfFile(cur) ?? "") + "|" + bakName);
        }
        catch { }
    }

    private static (bool ok, string? error) RepairWallpaper()
    {
        try
        {
            string baselineFile = Path.Combine(GuardDir, "wallpaper.baseline");
            if (!File.Exists(baselineFile)) return (false, "Brak zapisanej kopii tapety do przywrócenia.");
            var parts = File.ReadAllText(baselineFile).Split('|');
            string bakName = parts.Length > 2 ? parts[2] : "wallpaper-backup.img";
            string bakPath = Path.Combine(GuardDir, bakName);
            if (!File.Exists(bakPath)) return (false, "Plik kopii tapety nie istnieje.");

            string target = Path.Combine(GuardDir, "wallpaper-restored" + Path.GetExtension(bakName));
            File.Copy(bakPath, target, overwrite: true);

            using (var k = Registry.CurrentUser.OpenSubKey(DesktopKey, writable: true))
                k?.SetValue("Wallpaper", target, RegistryValueKind.String);
            SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, target, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
            return (true, null);
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    private static (bool bad, string? detail) CheckCursor()
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(CursorsKey);
            if (k == null) return (false, null);
            foreach (var name in CursorNames)
            {
                var v = k.GetValue(name) as string;
                if (!string.IsNullOrEmpty(v) && IsSuspiciousLocation(Environment.ExpandEnvironmentVariables(v)))
                    return (true, $"Kursor „{name}” wskazuje podejrzany plik: {v}");
            }
        }
        catch { }
        return (false, null);
    }

    private static (bool ok, string? error) RepairCursor()
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(CursorsKey, writable: true);
            if (k == null) return (false, "Brak klucza kursorów.");
            foreach (var name in CursorNames) k.DeleteValue(name, throwOnMissingValue: false);
            k.SetValue("", "", RegistryValueKind.String);   
            SystemParametersInfo(SPI_SETCURSORS, 0, null, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
            return (true, null);
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    private static (bool bad, string? detail) CheckFileIcons()
    {
        try
        {
            using (var ex = Registry.ClassesRoot.OpenSubKey(@"exefile\DefaultIcon"))
            {
                var v = ex?.GetValue(null) as string;
                if (!string.IsNullOrEmpty(v)
                    && IsSuspiciousLocation(Environment.ExpandEnvironmentVariables(v.Split(',')[0])))
                    return (true, $"Ikona plików EXE podmieniona: {v}");
            }
            foreach (var root in new[] { Registry.CurrentUser, Registry.LocalMachine })
            {
                using var k = root.OpenSubKey(ShellIconsKey);
                if (k == null) continue;
                foreach (var name in k.GetValueNames())
                {
                    var v = k.GetValue(name) as string;
                    if (!string.IsNullOrEmpty(v)
                        && IsSuspiciousLocation(Environment.ExpandEnvironmentVariables(v.Split(',')[0])))
                        return (true, $"Nadpisanie ikony #{name} → {v}");
                }
            }
        }
        catch { }
        return (false, null);
    }

    private static (bool ok, string? error) RepairFileIcons()
    {
        try
        {
            using (var ex = Registry.ClassesRoot.OpenSubKey(@"exefile\DefaultIcon", writable: true))
                ex?.SetValue(null, "%1", RegistryValueKind.ExpandString);
            foreach (var root in new[] { Registry.CurrentUser, Registry.LocalMachine })
            {
                using var k = root.OpenSubKey(ShellIconsKey, writable: true);
                if (k == null) continue;
                foreach (var name in k.GetValueNames().ToArray())
                {
                    var v = k.GetValue(name) as string;
                    if (!string.IsNullOrEmpty(v)
                        && IsSuspiciousLocation(Environment.ExpandEnvironmentVariables(v.Split(',')[0])))
                        k.DeleteValue(name, throwOnMissingValue: false);
                }
            }
            return (true, null);
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    private const uint SPI_SETDESKWALLPAPER = 0x0014;
    private const uint SPI_SETCURSORS       = 0x0057;
    private const uint SPIF_UPDATEINIFILE   = 0x01;
    private const uint SPIF_SENDCHANGE      = 0x02;

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SystemParametersInfo(uint uiAction, uint uiParam, string? pvParam, uint fWinIni);

    private static (bool bad, string? detail) CheckMbr()
    {
        try
        {
            using var fs = new FileStream(@"\\.\PhysicalDrive0", FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

            var buf = new byte[1024];
            int read = fs.Read(buf, 0, 1024);
            if (read < 512) return (false, "Nie udało się odczytać sektora rozruchowego.");

            bool sig = buf[510] == 0x55 && buf[511] == 0xAA;
            if (!sig) return (true, "Brak sygnatury rozruchowej 0x55AA na dysku 0 — wymazany MBR/bootloader.");

            byte firstPartType = buf[0x1C2];

            if (firstPartType == 0xEE)
            {
                if (read < 1024) return (false, "Nie udało się odczytać nagłówka GPT (LBA1).");

                bool gpt = buf[512] == 0x45 && buf[513] == 0x46 && buf[514] == 0x49 && buf[515] == 0x20
                        && buf[516] == 0x50 && buf[517] == 0x41 && buf[518] == 0x52 && buf[519] == 0x54;
                if (!gpt)
                    return (true, "Uszkodzony nagłówek GPT (brak sygnatury \"EFI PART\" w LBA1) — " +
                                  "wymazana/nadpisana tablica partycji (wiper/bootkit, np. Ana.exe).");
                return (false, null);
            }

            bool codeEmpty = true;
            for (int i = 0; i < 440 && codeEmpty; i++) if (buf[i] != 0) codeEmpty = false;
            if (codeEmpty) return (true, "Kod rozruchowy klasycznego MBR wyzerowany (możliwy wiper/bootkit).");

            bool partEmpty = true;
            for (int i = 0x1BE; i < 0x1FE && partEmpty; i++) if (buf[i] != 0) partEmpty = false;
            if (partEmpty) return (true, "Tablica partycji MBR pusta — brak partycji rozruchowej (możliwy wiper).");
        }
        catch (UnauthorizedAccessException) { return (false, "Brak uprawnień do odczytu MBR (uruchom jako administrator)."); }
        catch { return (false, null); }
        return (false, null);
    }

    private static (string Path, string Tool)[]? _uacKeys;
    private static (string Path, string Tool)[] UacBypassKeys =>
        _uacKeys ??= LoadUacKeys();

    private static (string Path, string Tool)[] LoadUacKeys()
    {
        var list = new List<(string, string)>();
        foreach (var entry in Data.SignatureStore.List("uac_bypass_keys"))
        {
            var parts = entry.Split('|', 2);
            if (parts.Length == 2) list.Add((parts[0], parts[1]));
        }
        return list.ToArray();
    }

    private static (bool bad, string? detail) CheckUacBypass()
    {
        var hits = new List<string>();
        foreach (var (path, tool) in UacBypassKeys)
        {
            try
            {
                using var k = Registry.CurrentUser.OpenSubKey(path);
                if (k == null) continue;

                var def = k.GetValue(null) as string;
                bool hasDelegate = Array.Exists(k.GetValueNames(), n => n.Equals("DelegateExecute", StringComparison.OrdinalIgnoreCase));
                if (!string.IsNullOrWhiteSpace(def) || hasDelegate)
                    hits.Add($"{tool}: HKCU\\{path}" + (string.IsNullOrWhiteSpace(def) ? " (DelegateExecute)" : $" = {def}"));
            }
            catch { }
        }
        return hits.Count > 0 ? (true, string.Join("; ", hits)) : (false, null);
    }

    private static (bool ok, string? error) RepairUacBypass()
    {
        foreach (var (path, _) in UacBypassKeys)
        {
            try
            {
                var top = path.Split('\\')[1];   
                using var classes = Registry.CurrentUser.OpenSubKey(@"Software\Classes", writable: true);
                if (classes?.OpenSubKey(top) != null)
                    classes.DeleteSubKeyTree(top, throwOnMissingSubKey: false);
            }
            catch { }
        }
        return (true, null);
    }

    private const string WinlogonAuto = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

    private static (bool bad, string? detail) CheckAutoLogon()
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(WinlogonAuto);
            if (k == null) return (false, null);
            var auto = k.GetValue("AutoAdminLogon") as string;
            bool on = auto == "1" || (int.TryParse(auto, out var a) && a == 1);
            var pw = k.GetValue("DefaultPassword") as string;
            if (on && !string.IsNullOrEmpty(pw))
                return (true, "AutoAdminLogon=1 z zapisanym DefaultPassword");
            if (on)
                return (true, "AutoAdminLogon=1 (automatyczne logowanie włączone)");
        }
        catch { }
        return (false, null);
    }

    private static (bool ok, string? error) RepairAutoLogon()
    {
        using var k = Registry.LocalMachine.OpenSubKey(WinlogonAuto, writable: true);
        if (k == null) return (false, "Brak dostępu do klucza Winlogon.");
        k.SetValue("AutoAdminLogon", "0", RegistryValueKind.String);
        k.DeleteValue("DefaultPassword", throwOnMissingValue: false);
        k.DeleteValue("DefaultUserName", throwOnMissingValue: false);
        return (true, null);
    }

    private static int? ReadInt(RegistryKey root, string subKey, string valueName)
    {
        try
        {
            using var k = root.OpenSubKey(subKey);
            var v = k?.GetValue(valueName);
            if (v is int i) return i;
            if (v != null && int.TryParse(v.ToString(), out var p)) return p;
        }
        catch { }
        return null;
    }
}
