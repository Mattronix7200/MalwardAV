using System.Diagnostics;

namespace Malward.Engine.Util;

public static class Paths
{
    public static string ExeDir { get; } = ResolveExeDir();

    public static string AppDataDir { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward");

    public static string BinDir    => ExeDir;
    public static string DataDir   => Path.Combine(AppDataDir, "data");
    public static string QuarantineDir => Path.Combine(AppDataDir, "quarantine");

    public static string WorkingDir => Path.Combine(AppDataDir, "engine", "working");
    public static string BasesDir  => Path.Combine(ExeDir, "_bases");

    public static string SettingsFile  => Path.Combine(DataDir, "settings.json");

    public static string VpsVdeb       => Path.Combine(DataDir, "vps.vdeb");
    public static string HeurVdeb      => Path.Combine(DataDir, "heur.vdeb");
    public static string WhitelistVdeb => Path.Combine(DataDir, "rf-whitelist.vdeb");

    public static string VpsVdebReadable => PreferExisting(VpsVdeb,
        Path.Combine(ExeDir, "data", "vps.vdeb"),
        Path.Combine(BasesDir, "engine", "vps.vdeb"));
    public static string HeurVdebReadable => PreferExisting(HeurVdeb,
        Path.Combine(ExeDir, "data", "heur.vdeb"),
        Path.Combine(BasesDir, "heur", "heur.vdeb"));
    public static string WhitelistVdebReadable => PreferExisting(WhitelistVdeb,
        Path.Combine(ExeDir, "data", "rf-whitelist.vdeb"),
        Path.Combine(BasesDir, "engine", "rf-whitelist.vdeb"));

    public static string HeurScanner   => Path.Combine(ExeDir, "heurscanner.exe");
    public static string MlaScanner    => Path.Combine(ExeDir, "mla_scanner.exe");
    public static string SevenZipExe   => Path.Combine(ExeDir, "7z.exe");
    public static string SevenZipDll   => Path.Combine(ExeDir, "7z.dll");

    public static string QuarantineFile => Path.Combine(QuarantineDir, "quarantine.QB");

    public static void EnsureDirs()
    {
        Directory.CreateDirectory(DataDir);
        Directory.CreateDirectory(QuarantineDir);
        MigrateFromLegacyDataDir();
    }

    private static void MigrateFromLegacyDataDir()
    {
        var legacyDir = Path.Combine(ExeDir, "data");
        if (!Directory.Exists(legacyDir)) return;
        string[] files = {
            "vps.vdeb", "heur.vdeb", "rf-whitelist.vdeb",
            "settings.json", "scan-stats.json", "scan-history.json",
            "gui-settings.json"
        };
        foreach (var fn in files)
        {
            var src = Path.Combine(legacyDir, fn);
            var dst = Path.Combine(DataDir, fn);
            if (File.Exists(src) && !File.Exists(dst))
                try { File.Copy(src, dst); } catch {  }
        }
    }

    private static string ResolveExeDir()
    {
        try
        {
            var exe = Process.GetCurrentProcess().MainModule?.FileName;
            if (!string.IsNullOrEmpty(exe))
            {
                var d = Path.GetDirectoryName(exe);
                if (!string.IsNullOrEmpty(d)) return d;
            }
        }
        catch {  }
        return AppContext.BaseDirectory;
    }

    private static string PreferExisting(string primary, string fallback)
        => File.Exists(primary) ? primary
         : File.Exists(fallback) ? fallback
         : primary;

    private static string PreferExisting(string primary, string legacy, string fallback)
        => File.Exists(primary) ? primary
         : File.Exists(legacy) ? legacy
         : File.Exists(fallback) ? fallback
         : primary;
}
