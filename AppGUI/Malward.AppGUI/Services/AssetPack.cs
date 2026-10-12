using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;

namespace Malward.AppGUI.Services;

public sealed class AssetPack
{
    private readonly Dictionary<string, byte[]> _files =
        new(StringComparer.OrdinalIgnoreCase);

    public bool Loaded => _files.Count > 0;
    public int Count => _files.Count;

    public static AssetPack? TryLoad(string vdebPath)
    {
        try
        {
            if (!File.Exists(vdebPath)) return null;

            return TryLoadBytes(File.ReadAllBytes(vdebPath));
        }
        catch { return null; }
    }

    public static AssetPack? TryLoadBytes(byte[] raw)
    {
        try
        {
            var pack = new AssetPack();
            using var ms = new MemoryStream(raw, writable: false);
            using var zip = new ZipArchive(ms, ZipArchiveMode.Read);
            foreach (var entry in zip.Entries)
            {
                if (string.IsNullOrEmpty(entry.Name)) continue;
                using var es = entry.Open();
                using var buf = new MemoryStream();
                es.CopyTo(buf);
                pack._files[Normalize(entry.FullName)] = buf.ToArray();
            }
            return pack.Loaded ? pack : null;
        }
        catch { return null; }
    }

    public static AssetPack? TryLoadFolder(string assetsDir)
    {
        try
        {
            if (!Directory.Exists(assetsDir)) return null;
            var pack = new AssetPack();
            foreach (var file in Directory.EnumerateFiles(assetsDir, "*", SearchOption.AllDirectories))
            {
                var rel = Path.GetRelativePath(assetsDir, file);
                pack._files[Normalize(rel)] = File.ReadAllBytes(file);
            }
            return pack.Loaded ? pack : null;
        }
        catch { return null; }
    }

    public bool TryGet(string relPath, out byte[] data)
        => _files.TryGetValue(Normalize(relPath), out data!);

    private static string Normalize(string p)
        => p.Replace('\\', '/').TrimStart('/');

    public static string ContentTypeFor(string path)
    {
        var ext = Path.GetExtension(path).ToLowerInvariant();
        return ext switch
        {
            ".html" or ".htm" => "text/html; charset=utf-8",
            ".css"  => "text/css; charset=utf-8",
            ".js"   => "application/javascript; charset=utf-8",
            ".json" => "application/json; charset=utf-8",
            ".svg"  => "image/svg+xml",
            ".png"  => "image/png",
            ".jpg" or ".jpeg" => "image/jpeg",
            ".gif"  => "image/gif",
            ".ico"  => "image/x-icon",
            ".woff" => "font/woff",
            ".woff2"=> "font/woff2",
            ".ttf"  => "font/ttf",
            _       => "application/octet-stream",
        };
    }
}
