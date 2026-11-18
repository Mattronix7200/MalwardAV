using System.Text.Json;
using System.Text.RegularExpressions;

namespace Malward.ResidentShield;

internal static class LogEnglish
{
    private static readonly (Regex Pattern, string Replacement)[] Rules =
    {
        (R(@"(\d+) plików zaszyfrowanych \(entropia ≥ ([\d.,]+), maks\. ([\d.,]+)\)"), "$1 files encrypted (entropy ≥ $2, max $3)"),
        (R(@"(\d+) plików dostało rozszerzenie ransomware '([^']*)'"), "$1 files received the ransomware extension '$2'"),
        (R(@"\(możliwe wykonanie/wstrzyknięcie kodu\)"), "(possible code execution/injection)"),
        (R(@"\(przez ([^)]+)\)"), "(via $1)"),
        (R(@"Podejrzana linia poleceń: "), "Suspicious command line: "),
        (R(@"Niepodpisana biblioteka (.+?) załadowana do zaufanego procesu "), "Unsigned library $1 loaded into the trusted process "),
        (R(@"Niepodpisana biblioteka "), "Unsigned library "),
        (R(@"podszycie się pod jego reputację"), "borrowing its reputation"),
        (R(@"Bombardowanie procesami"), "Process bombing"),
        (R(@"Dodano (\d+) wpis\(ów\) autostartu: "), "Added $1 autostart entr(ies): "),
        (R(@"Masowa modyfikacja plików: (\d+) plików w (\d+) ms"), "Mass file modification: $1 files in $2 ms"),
        (R(@"Modyfikacja klucza bezpieczeństwa: "), "Security key modified: "),
        (R(@"Proces ""([^""]+)"" uruchomiony spoza System32: "), "Process \"$1\" started outside System32: "),
        (R(@"Proces kopiuje własny plik wykonywalny \((\d+)×\), np\. (.+?) — cecha robaka/replikatora"), "Process copies its own executable ($1×), e.g. $2 — worm/replicator trait"),
        (R(@"Proces spawnuje (\d+) kopii samego siebie"), "Process spawns $1 copies of itself"),
        (R(@"Proces utworzył (\d+) nowych plików wykonywalnych"), "Process created $1 new executables"),
        (R(@"Proces z niezaufanej lokalizacji tworzy (\d+) procesów potomnych"), "Process from an untrusted location creates $1 child processes"),
        (R(@"Proces zapisuje kod do (\d+) cudzych plików wykonywalnych \(infekcja PE\): "), "Process writes code into $1 foreign executables (PE infection): "),
        (R(@"Proces zmodyfikował cudzy plik wykonywalny: "), "Process modified a foreign executable: "),
        (R(@"Próba zakończenia powłoki systemu: "), "Attempt to terminate the system shell: "),
        (R(@"Próba zakończenia procesu ochronnego: "), "Attempt to terminate a protection process: "),
        (R(@"Sabotaż kopii zapasowych / odzyskiwania: "), "Backup/recovery sabotage: "),
        (R(@"Seria poleceń rozpoznawczych \((\d+)\): "), "Series of reconnaissance commands ($1): "),
        (R(@"Utworzono notkę szantażową: "), "Ransom note created: "),
        (R(@"Utworzono usługę systemową: "), "System service created: "),
        (R(@"Zapis do chronionego katalogu: "), "Write to a protected folder: "),
        (R(@"Zmiana kont użytkowników: "), "User account change: "),
        (R(@"Proces utworzony przez wykryte wcześniej zagrożenie"), "Process created by a previously detected threat"),
        (R(@"program z lokalizacji powiązanej z wykrytym zagrożeniem"), "a program from a location tied to that threat"),
        (R(@"potomek zagrożenia"), "a descendant of the threat"),
        (R(@"Usunięto wpis: "), "Removed entry: "),
        (R(@"\(było: ([^)]*)\)"), "(was: $1)"),
        (R(@"\(wpis usunięty\)"), "(entry deleted)"),
        (R(@"Plik o nazwie systemowej \(([^)]+)\) uruchamiany spoza katalogu systemowego: "), "File with a system name ($1) running outside the system folder: "),
        (R(@" — podszycie pod komponent Windows"), " — impersonating a Windows component"),
    };

    private static readonly Regex Bracketed = R(@"\[([^\[\]]{3,120})\]");
    private static readonly Regex PipeTail = R(@" \| ([^|]{3,120})$");

    private static Dictionary<string, string>? _dict;
    private static long _dictLoadedTicks;

    private static Regex R(string pattern) => new(pattern, RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static string Apply(string msg)
    {
        if (string.IsNullOrEmpty(msg) || !LooksPolish(msg)) return msg;
        try
        {
            var dict = Dictionary();
            if (dict != null)
            {
                msg = Bracketed.Replace(msg, m =>
                    dict.TryGetValue(m.Groups[1].Value, out var en) ? "[" + en + "]" : m.Value);
                msg = PipeTail.Replace(msg, m =>
                    dict.TryGetValue(m.Groups[1].Value.Trim(), out var en) ? " | " + en : m.Value);
            }

            foreach (var (pattern, replacement) in Rules)
                msg = pattern.Replace(msg, replacement);
        }
        catch { }
        return msg;
    }

    private static bool LooksPolish(string s)
    {
        foreach (var c in s)
            if ("ąćęłńóśźżĄĆĘŁŃÓŚŹŻ".IndexOf(c) >= 0) return true;
        return s.Contains("plików", StringComparison.Ordinal)
            || s.Contains("Proces ", StringComparison.Ordinal)
            || s.Contains("przez ", StringComparison.Ordinal);
    }

    private static Dictionary<string, string>? Dictionary()
    {
        long now = Environment.TickCount64;
        if (_dict != null && now - Interlocked.Read(ref _dictLoadedTicks) < 600_000) return _dict;
        try
        {
            var path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Malward", "data", "i18n-en.json");
            if (File.Exists(path))
                _dict = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllBytes(path));
        }
        catch { }
        Interlocked.Exchange(ref _dictLoadedTicks, now);
        return _dict;
    }
}
