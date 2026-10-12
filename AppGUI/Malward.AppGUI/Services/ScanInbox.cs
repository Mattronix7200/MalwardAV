using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;

namespace Malward.AppGUI.Services;

public static class ScanInbox
{
    public static string Path => System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "inbox", "scan-request.txt");

    public static void Append(IEnumerable<string> paths)
    {
        try
        {
            var sb = new StringBuilder();
            foreach (var p in paths)
            {
                var t = (p ?? "").Trim().Trim('"');
                if (t.Length > 0) sb.Append(t).Append('\n');
            }
            if (sb.Length == 0) return;

            var bytes = new UTF8Encoding(false).GetBytes(sb.ToString());
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
            for (int attempt = 0; attempt < 25; attempt++)
            {
                try
                {
                    using var fs = new FileStream(Path, FileMode.Append,
                        FileAccess.Write, FileShare.ReadWrite);
                    fs.Write(bytes, 0, bytes.Length);
                    return;
                }
                catch (IOException) { Thread.Sleep(15); }
            }
        }
        catch { }
    }
}
