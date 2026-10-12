using System.Text.Json.Nodes;

namespace Malward.Engine.Core;

public sealed class ScanPlan
{
    public sealed record FolderTarget(string Path, string[] Extensions)
    {
        public bool Matches(string file)
        {
            if (Extensions.Length == 0) return true;
            var ext = System.IO.Path.GetExtension(file);
            if (ext.Length < 2) return false;
            foreach (var e in Extensions)
                if (ext.AsSpan(1).Equals(e, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }
    }

    public string Name { get; init; } = "custom";

    public bool Memory   { get; set; }
    public bool Tasks    { get; set; }
    public bool Registry { get; set; }
    public bool Drivers  { get; set; }
    public bool Rootkit  { get; set; }
    public List<FolderTarget> Folders { get; } = new();

    public bool IsEmpty => !Memory && !Tasks && !Registry && !Drivers && !Rootkit && Folders.Count == 0;

    private static readonly string[] ExecOnly = { "exe", "dll" };
    private static readonly string[] AllFiles = Array.Empty<string>();

    private static string Env(string var) => Environment.GetEnvironmentVariable(var) ?? "";
    private static string Win => Environment.GetFolderPath(Environment.SpecialFolder.Windows);

    public static ScanPlan Quick()
    {
        var p = new ScanPlan
        {
            Name = "quick",
            Memory = true, Tasks = true, Registry = true, Drivers = true, Rootkit = true,
        };
        void Add(string path, string[] exts)
        {
            if (!string.IsNullOrEmpty(path) && Directory.Exists(path))
                p.Folders.Add(new FolderTarget(path, exts));
        }

        Add(Path.Combine(Win, "System32"), ExecOnly);
        Add(Path.Combine(Win, "SysWOW64"), ExecOnly);
        Add(Path.Combine(Path.GetPathRoot(Win) ?? @"C:\", "Users"), AllFiles);
        Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), AllFiles);
        Add(Env("TEMP"), AllFiles);
        Add(Env("APPDATA"), AllFiles);
        Add(Env("LOCALAPPDATA"), AllFiles);
        Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), ExecOnly);
        Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), ExecOnly);
        return p;
    }

    public static ScanPlan Full()
    {
        var p = new ScanPlan
        {
            Name = "full",
            Memory = true, Tasks = true, Registry = true, Drivers = true, Rootkit = true,
        };
        try
        {
            foreach (var d in DriveInfo.GetDrives())
            {
                if (d.DriveType != DriveType.Fixed || !d.IsReady) continue;
                p.Folders.Add(new FolderTarget(d.RootDirectory.FullName, AllFiles));
            }
        }
        catch { }
        if (p.Folders.Count == 0) p.Folders.Add(new FolderTarget(@"C:\", AllFiles));
        return p;
    }

    public static ScanPlan SingleTarget(string path)
    {
        var p = new ScanPlan { Name = "target" };

        if (Directory.Exists(path)) p.Folders.Add(new FolderTarget(path, AllFiles));
        return p;
    }

    public static string DriversDir => Path.Combine(Win, "System32", "drivers");

    public static ScanPlan? FromJson(string json)
    {
        try
        {
            if (JsonNode.Parse(json) is not JsonObject o) return null;
            var name = o["name"]?.GetValue<string>() ?? "custom";
            switch (name.ToLowerInvariant())
            {
                case "quick": return Quick();
                case "full":  return Full();
            }

            var p = new ScanPlan
            {
                Name = name,
                Memory   = o["memory"]?.GetValue<bool>()   ?? false,
                Tasks    = o["tasks"]?.GetValue<bool>()    ?? false,
                Registry = o["registry"]?.GetValue<bool>() ?? false,
                Drivers  = o["drivers"]?.GetValue<bool>()  ?? false,
                Rootkit  = o["rootkit"]?.GetValue<bool>()  ?? false,
            };
            if (o["folders"] is JsonArray arr)
                foreach (var n in arr)
                {
                    if (n is JsonObject f)
                    {
                        var path = f["path"]?.GetValue<string>() ?? "";
                        var exts = (f["ext"] as JsonArray)?
                                   .Select(x => (x?.GetValue<string>() ?? "").TrimStart('.'))
                                   .Where(x => x.Length > 0).ToArray() ?? AllFiles;
                        if (path.Length > 0) p.Folders.Add(new FolderTarget(path, exts));
                    }
                    else if (n?.GetValue<string>() is string s && s.Length > 0)
                        p.Folders.Add(new FolderTarget(s, AllFiles));
                }
            return p;
        }
        catch { return null; }
    }

    public IEnumerable<string> ActiveStageNames()
    {
        if (Memory) yield return "memory";
        if (Rootkit) yield return "rootkit";
        if (Drivers) yield return "drivers";
        if (Tasks) yield return "tasks";
        if (Registry) yield return "registry";
        if (Folders.Count > 0) yield return "files";
    }
}
