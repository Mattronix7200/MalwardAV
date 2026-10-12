using System.Collections.Generic;
using System.IO;

namespace Malward.AppGUI.Services;

public sealed record VerificationIssue(string File, string Description, bool Critical);

public sealed record VerificationResult(IReadOnlyList<VerificationIssue> Issues,
                                        string? MalscanPath,
                                        string? EngineDir)
{
    public bool HasCritical => Issues.Any(i => i.Critical);
    public bool HasWarnings => Issues.Any(i => !i.Critical);
}

public static class FileVerification
{
    public static VerificationResult Verify(string? engineOverride = null)
    {
        var issues = new List<VerificationIssue>();
        var malscan = EngineLocator.FindMalscan(engineOverride);

        if (malscan == null)
        {
            issues.Add(new VerificationIssue("malscan.exe",
                "Brak silnika antywirusowego malscan.exe. Wymagana reinstalacja.", true));
            return new VerificationResult(issues, null, null);
        }

        var engineDir = Path.GetDirectoryName(malscan)!;

        var sevenZipExe = Path.Combine(engineDir, "7z.exe");
        var sevenZipDll = Path.Combine(engineDir, "7z.dll");
        if (!File.Exists(sevenZipExe))
            issues.Add(new VerificationIssue("7z.exe",
                "Brak 7z.exe — skanowanie archiwów wyłączone.", false));
        if (!File.Exists(sevenZipDll))
            issues.Add(new VerificationIssue("7z.dll",
                "Brak 7z.dll — skanowanie archiwów wyłączone.", false));

        var heurScanner = Path.Combine(engineDir, "heurscanner.exe");
        if (!File.Exists(heurScanner))
            issues.Add(new VerificationIssue("heurscanner.exe",
                "Brak heurscanner.exe (yara) — heurystyka YARA wyłączona.", false));

        var appDataDbDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Malward", "data");
        var dataDir  = Path.Combine(engineDir, "data");
        var basesDir = Path.Combine(engineDir, "_bases");

        bool VdbExists(string name)
            => File.Exists(Path.Combine(appDataDbDir, name))
            || File.Exists(Path.Combine(dataDir,      name));

        if (!VdbExists("vps.vdeb") && !File.Exists(Path.Combine(basesDir, "engine", "vps.vdeb")))
            issues.Add(new VerificationIssue("vps.vdeb",
                "Brak bazy VPS (vps.vdeb). Uruchom `Update` żeby pobrać z serwera.", false));

        var heurFallback = Path.Combine(basesDir, "heur");
        bool heurYacExists = Directory.Exists(heurFallback)
            && (File.Exists(Path.Combine(heurFallback, "001.yac"))
             || File.Exists(Path.Combine(heurFallback, "002.yac"))
             || File.Exists(Path.Combine(heurFallback, "003.yac")));
        if (!VdbExists("heur.vdeb") && !heurYacExists)
            issues.Add(new VerificationIssue("heur.vdeb",
                "Brak bazy heurystyki. Uruchom `Update`.", false));

        var configNames = new[]
        {
            Malward.Engine.Cloud.ConfigKeyFile.FileName,
            Malward.Engine.Cloud.ConfigKeyFile.LegacyFileName,
        };
        bool configPresent = configNames.Any(n =>
               File.Exists(Path.Combine(engineDir, n))
            || File.Exists(Path.Combine(AppContext.BaseDirectory, n))
            || File.Exists(Path.Combine(appDataDbDir, n)));

        bool envSecret = !string.IsNullOrWhiteSpace(
            Environment.GetEnvironmentVariable("MALWARD_AUTH_PSK"));
        if (!configPresent && !envSecret)
            issues.Add(new VerificationIssue(Malward.Engine.Cloud.ConfigKeyFile.FileName,
                "Brak pliku konfiguracyjnego z poświadczeniami chmury. Wymagana reinstalacja.", true));

        return new VerificationResult(issues, malscan, engineDir);
    }
}
