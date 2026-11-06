using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;

namespace Malward.AppGUI.Services;

public static class ScheduleInbox
{
    public static string Path => System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "inbox", "scheduled-scan.txt");

    public static bool TryHandOver(string[] args)
    {
        int idx = Array.FindIndex(args, a =>
            string.Equals(a, "--scheduled-scan", StringComparison.OrdinalIgnoreCase));
        if (idx < 0) return false;

        string mode = idx + 1 < args.Length ? args[idx + 1] : "quick";
        var folders = new List<string>();
        for (int i = idx + 2; i < args.Length - 1; i++)
            if (string.Equals(args[i], "--folder", StringComparison.OrdinalIgnoreCase))
                folders.Add(args[++i]);

        var sb = new StringBuilder();
        sb.Append(mode.Trim());
        foreach (var f in folders)
        {
            var t = (f ?? "").Trim().Trim('"');
            if (t.Length > 0) sb.Append('\t').Append(t);
        }
        sb.Append('\n');

        try
        {
            var bytes = new UTF8Encoding(false).GetBytes(sb.ToString());
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
            for (int attempt = 0; attempt < 25; attempt++)
            {
                try
                {
                    using var fs = new FileStream(Path, FileMode.Append,
                        FileAccess.Write, FileShare.ReadWrite);
                    fs.Write(bytes, 0, bytes.Length);
                    return true;
                }
                catch (IOException) { Thread.Sleep(15); }
            }
        }
        catch { }
        return false;
    }

    public static (string Mode, List<string> Folders)? TakeRequest()
    {
        try
        {
            if (!File.Exists(Path)) return null;
            var text = File.ReadAllText(Path);
            try { File.Delete(Path); } catch { }

            foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var parts = line.Trim().Split('\t', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 0) continue;
                var mode = parts[0].Trim();
                if (mode.Length == 0) continue;
                var folders = new List<string>();
                for (int i = 1; i < parts.Length; i++) folders.Add(parts[i].Trim());
                return (mode, folders);
            }
        }
        catch { }
        return null;
    }
}
