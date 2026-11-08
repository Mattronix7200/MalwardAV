using Malward.Engine.Quarantine;

namespace Malward.ConsoleShell;

public static class QuarantineShell
{
    public static int Run(CommandLine cl)
    {
        if (!Elevation.IsAdministrator)
        {
            Elevation.WarnNotElevated("the quarantine manager");
            return 3;
        }

        var store = new QuarantineStore();

        if (cl.Has("s", "list"))        return List(store);
        if (cl.Has("v", "view-item"))   return View(store, cl.Value("v", "view-item"));
        if (cl.Has("lp", "search"))     return Search(store, cl.Value("lp", "search"));
        if (cl.Has("x", "extract"))     return Extract(store, cl);
        if (cl.Has("rvt", "revert"))    return Revert(store, cl.Value("rvt", "revert"));

        Help.Quarantine();
        return 2;
    }

    private static void Print(IReadOnlyList<QbFormat.Entry> items)
    {
        var rows = new List<IReadOnlyList<string>>();
        foreach (var e in items)
            rows.Add(new[]
            {
                Short(e.Id),
                e.Detection,
                e.Size.ToString("N0"),
                Stamp(e.QuarantinedTs).ToString("yyyy-MM-dd HH:mm:ss"),
                e.OriginalPath,
            });

        Con.Table(new[] { "ID", "DETECTION", "SIZE", "QUARANTINED", "ORIGINAL PATH" }, rows,
                  rows.Select(_ => Tone.Plain).ToList());
    }

    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    private static DateTime Stamp(ulong ts) =>
        DateTimeOffset.FromUnixTimeSeconds((long)ts).LocalDateTime;

    private static string Short(Guid id) => id.ToString("N")[..8];

    private static int List(QuarantineStore store)
    {
        var items = store.List();
        if (items.Count == 0) { Console.WriteLine("Quarantine is empty."); return 0; }

        Print(items);
        Console.WriteLine();
        Console.WriteLine($"{items.Count} item(s), {store.TotalSize():N0} bytes total.");
        return 0;
    }

    private static int View(QuarantineStore store, string? id)
    {
        var e = Find(store, id);
        if (e == null) return 1;

        Console.WriteLine($"ID           : {e.Id}");
        Console.WriteLine($"Detection    : {e.Detection}");
        Console.WriteLine($"Original path: {e.OriginalPath}");
        Console.WriteLine($"Size         : {e.Size:N0} bytes");
        Console.WriteLine($"SHA-256      : {Hex(e.Sha256)}");
        Console.WriteLine($"Quarantined  : {Stamp(e.QuarantinedTs):yyyy-MM-dd HH:mm:ss}");
        Console.WriteLine($"Stored size  : {e.PayloadSize:N0} bytes (encrypted)");
        return 0;
    }

    private static int Search(QuarantineStore store, string? needle)
    {
        if (string.IsNullOrWhiteSpace(needle))
        {
            Console.Error.WriteLine("[!] /lp needs something to look for: a name, a path, a detection, an ID or a date.");
            return 2;
        }

        var hits = store.List().Where(e =>
                Contains(e.OriginalPath, needle)
             || Contains(Path.GetFileName(e.OriginalPath), needle)
             || Contains(e.Detection, needle)
             || Contains(e.Id.ToString("N"), needle)
             || Contains(Hex(e.Sha256), needle)
             || Contains(Stamp(e.QuarantinedTs).ToString("yyyy-MM-dd HH:mm:ss"), needle))
            .ToList();

        if (hits.Count == 0) { Console.WriteLine($"Nothing matches \"{needle}\"."); return 1; }

        Print(hits);
        Console.WriteLine();
        Console.WriteLine($"{hits.Count} match(es).");
        return 0;
    }

    private static int Extract(QuarantineStore store, CommandLine cl)
    {
        var id = cl.Value("x", "extract");
        var e = Find(store, id);
        if (e == null) return 1;

        var rest = cl.Positional();
        string dest = rest.Count > 0 ? rest[0] : Directory.GetCurrentDirectory();
        try { Directory.CreateDirectory(dest); }
        catch (Exception ex) { Console.Error.WriteLine($"[!] {dest}: {ex.Message}"); return 1; }

        try
        {
            var written = store.Extract(e.Id, dest, Path.GetFileName(e.OriginalPath));
            if (written == null) { Console.Error.WriteLine("[!] Extraction failed."); return 1; }
            Console.WriteLine($"[+] Extracted to {written}");
            Console.WriteLine("    The item stays in quarantine.");
            return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine($"[!] {ex.Message}"); return 1; }
    }

    private static int Revert(QuarantineStore store, string? id)
    {
        var e = Find(store, id);
        if (e == null) return 1;

        Console.WriteLine($"Restoring {e.Detection} to {e.OriginalPath}");
        try
        {
            if (!store.Restore(e.Id))
            {
                Console.Error.WriteLine("[!] Restore failed — the original folder may be gone or in use.");
                return 1;
            }
        }
        catch (Exception ex) { Console.Error.WriteLine($"[!] {ex.Message}"); return 1; }

        Console.WriteLine("[+] Restored and removed from quarantine.");
        return 0;
    }

    private static QbFormat.Entry? Find(QuarantineStore store, string? id)
    {
        if (string.IsNullOrWhiteSpace(id))
        {
            Console.Error.WriteLine("[!] An item ID is required (see /quarmng /s).");
            return null;
        }

        var key = id.Trim().Replace("-", "");
        var matches = store.List()
            .Where(e => e.Id.ToString("N").StartsWith(key, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (matches.Count == 0) { Console.Error.WriteLine($"[!] No quarantine item with ID {id}."); return null; }
        if (matches.Count > 1)
        {
            Console.Error.WriteLine($"[!] {id} matches {matches.Count} items — give more characters.");
            return null;
        }
        return matches[0];
    }

    private static bool Contains(string haystack, string needle) =>
        haystack.Contains(needle, StringComparison.OrdinalIgnoreCase);
}
