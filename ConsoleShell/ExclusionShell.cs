using System.Text.Json;
using Malward.Engine.Util;

namespace Malward.ConsoleShell;

/// <summary>The /exclusions shell. Keeps its own list so the GUI scanner configuration is untouched.</summary>
public static class ExclusionShell
{
    private static string StorePath =>
        Path.Combine(Paths.DataDir, "malcsm-exclusions.json");

    public static int Run(CommandLine cl)
    {
        if (cl.Has("ea", "add-exclusion"))    return Add(cl.Value("ea", "add-exclusion"));
        if (cl.Has("er", "remove-exclusion")) return Remove(cl.Value("er", "remove-exclusion"));
        if (cl.Has("ev", "show-exclusions"))  return Show();

        Help.Exclusions();
        return 2;
    }

    public static List<string> Load()
    {
        try
        {
            if (!File.Exists(StorePath)) return new List<string>();
            var list = JsonSerializer.Deserialize<List<string>>(File.ReadAllText(StorePath));
            return list ?? new List<string>();
        }
        catch { return new List<string>(); }
    }

    private static bool Save(List<string> list)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(StorePath)!);
            File.WriteAllText(StorePath,
                JsonSerializer.Serialize(list, new JsonSerializerOptions { WriteIndented = true }));
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[!] cannot write {StorePath}: {ex.Message}");
            return false;
        }
    }

    private static int Add(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            Console.Error.WriteLine("[!] /ea needs a path: malcsm /exclusions /ea \"C:\\folder\"");
            return 2;
        }

        string full;
        try { full = Path.GetFullPath(path.Trim('"')); }
        catch (Exception ex) { Console.Error.WriteLine($"[!] {path}: {ex.Message}"); return 2; }

        if (!File.Exists(full) && !Directory.Exists(full))
            Console.WriteLine($"[i] {full} does not exist right now — the exclusion is stored anyway.");

        var list = Load();
        if (list.Any(e => e.Equals(full, StringComparison.OrdinalIgnoreCase)))
        {
            Console.WriteLine("[i] Already excluded.");
            return 0;
        }

        list.Add(full);
        if (!Save(list)) return 1;
        Console.WriteLine($"[+] Excluded (ID {list.Count}): {full}");
        return 0;
    }

    private static int Remove(string? id)
    {
        var list = Load();
        if (list.Count == 0) { Console.WriteLine("No exclusions to remove."); return 1; }

        if (!int.TryParse(id, out int n) || n < 1 || n > list.Count)
        {
            Console.Error.WriteLine($"[!] /er needs an ID between 1 and {list.Count} (see /ev).");
            return 2;
        }

        var removed = list[n - 1];
        list.RemoveAt(n - 1);
        if (!Save(list)) return 1;
        Console.WriteLine($"[+] Removed: {removed}");
        return 0;
    }

    private static int Show()
    {
        var list = Load();
        if (list.Count == 0) { Console.WriteLine("No exclusions defined."); return 0; }

        Console.WriteLine($"{"ID",-4} PATH");
        for (int i = 0; i < list.Count; i++)
            Console.WriteLine($"{i + 1,-4} {list[i]}");
        Console.WriteLine();
        Console.WriteLine($"{list.Count} exclusion(s) — stored in {StorePath}");
        return 0;
    }
}
