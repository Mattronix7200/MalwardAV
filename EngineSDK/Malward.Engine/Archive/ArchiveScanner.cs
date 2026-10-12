using System.Diagnostics;
using Malward.Engine.Util;

namespace Malward.Engine.Archive;

public sealed class ArchiveScanner
{
    private static readonly HashSet<string> _knownExt = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".zipx", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".tbz", ".tbz2",
        ".arj", ".lzh", ".lha", ".xz", ".txz", ".lzma", ".z", ".taz", ".cpio", ".zst", ".tzst",

        ".iso", ".img", ".vhd", ".vhdx", ".vmdk", ".vdi", ".qcow", ".qcow2",
        ".wim", ".swm", ".esd", ".dmg", ".hfs", ".squashfs", ".cramfs", ".ext", ".fat", ".ntfs", ".gpt", ".mbr",

        ".cab", ".msi", ".msp", ".msix", ".appx", ".nupkg", ".rpm", ".deb", ".pkg", ".xar", ".udf",

        ".jar", ".war", ".ear", ".apk", ".ipa", ".xpi", ".crx", ".odt", ".ods", ".odp", ".epub",
    };

    private static readonly HashSet<string> _probeExt = new(StringComparer.OrdinalIgnoreCase);

    private HashSet<string>? _overrideExt;

    public void ConfigureExtensions(IEnumerable<string>? extensions)
    {
        var list = extensions?.Select(e => e.Trim().TrimStart('*'))
                              .Where(e => e.Length > 0)
                              .Select(e => e.StartsWith('.') ? e : "." + e)

                              .Where(e => !e.Equals(".exe", StringComparison.OrdinalIgnoreCase)
                                       && !e.Equals(".sfx", StringComparison.OrdinalIgnoreCase))
                              .ToList();
        _overrideExt = (list is { Count: > 0 })
            ? new HashSet<string>(list, StringComparer.OrdinalIgnoreCase)
            : null;
    }

    private HashSet<string> KnownExt => _overrideExt ?? _knownExt;

    private readonly string? _sevenZip = Paths.SevenZipExe;

    private const long MaxExtractBytes   = 4L * 1024 * 1024 * 1024;
    private const int  MaxExtractEntries = 500_000;
    private const long MinFreeDiskBytes  = 512L * 1024 * 1024;

    private static long TryFreeSpace(string path)
    {
        try
        {
            var root = Path.GetPathRoot(Path.GetFullPath(path));
            return string.IsNullOrEmpty(root) ? -1 : new DriveInfo(root).AvailableFreeSpace;
        }
        catch { return -1; }
    }

    public bool IsArchivePath(string path)
    {
        var e = Path.GetExtension(path);
        if (KnownExt.Contains(e)) return true;

        if (_probeExt.Contains(e))  return CanList(path);
        return false;
    }

    public static bool IsArchive(string path)
    {
        var e = Path.GetExtension(path);
        if (_knownExt.Contains(e)) return true;
        if (_probeExt.Contains(e))
        {
            var sz = Paths.SevenZipExe;
            if (!File.Exists(sz)) return false;
            return TryList(sz, path) > 0;
        }
        return false;
    }

    private bool CanList(string path)
    {
        if (_sevenZip == null || !File.Exists(_sevenZip)) return false;
        return TryList(_sevenZip, path) > 0;
    }

    private static int TryList(string sevenZip, string archivePath)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = sevenZip,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            psi.ArgumentList.Add("l");
            psi.ArgumentList.Add("-ba");
            psi.ArgumentList.Add(archivePath);
            using var p = Process.Start(psi)!;
            string sout = p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            if (!p.WaitForExit(5000)) { try { p.Kill(true); } catch { } return -1; }
            if (p.ExitCode != 0) return -1;
            return sout.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length;
        }
        catch { return -1; }
    }

    public sealed record ArchiveEntryFinding(string EntryName, string Detection, string Source,
                                             string Display = "", bool Direct = true);

    public sealed record ArchiveResult(
        bool AnyDetected,
        IReadOnlyList<ArchiveEntryFinding> Findings,
        string? Error,
        bool PasswordProtected = false,

        bool Expanded = false
    );

    public delegate Core.DetectionResult ArchiveScanFn(string tempPath, string displayPath);

    private readonly record struct EntryInfo(string Path, long Size);

    public ArchiveResult ScanArchive(string archivePath, ArchiveScanFn scanFn, int timeoutSec = 300,
                                     Action<string>? onEntry = null, string? displayName = null)
    {
        var sevenZip = _sevenZip ?? Paths.SevenZipExe;
        if (!File.Exists(sevenZip))
            return new ArchiveResult(false, Array.Empty<ArchiveEntryFinding>(),
                $"7z.exe not found at {sevenZip}");

        var lib = SevenZipLib.Shared;
        if (lib != null)
        {
            var viaLib = ScanWithLibrary(lib, archivePath, scanFn, timeoutSec, onEntry, displayName);
            if (viaLib != null) return viaLib;
        }

        var (entries, listError, headerEncrypted) = ListEntries(sevenZip, archivePath, timeoutSec);
        if (headerEncrypted)
            return new ArchiveResult(false, Array.Empty<ArchiveEntryFinding>(),
                "Archive is encrypted", PasswordProtected: true);
        if (entries == null)
            return new ArchiveResult(false, Array.Empty<ArchiveEntryFinding>(), listError);

        var workRoot = Paths.WorkingDir;
        try { Directory.CreateDirectory(workRoot); }
        catch { workRoot = Path.GetTempPath(); }
        var workDir = Path.Combine(workRoot, $"arch-{Guid.NewGuid():N}");
        Directory.CreateDirectory(workDir);

        var findings = new List<ArchiveEntryFinding>();
        string archiveName = displayName ?? Path.GetFileName(archivePath);
        string? error = null;
        try
        {
            long budget = MaxExtractBytes;
            int scanned = 0;
            var deadline = Stopwatch.StartNew();

            foreach (var entry in entries)
            {
                if (++scanned > MaxExtractEntries)
                { error = "Too many entries in archive, truncated."; break; }
                if (deadline.Elapsed.TotalSeconds > timeoutSec)
                { error = "Archive scan timeout"; break; }

                if (entry.Size > budget)
                { error = "Corrupted data in archive detected, skipping."; break; }
                long free = TryFreeSpace(workDir);
                if (free >= 0 && free < MinFreeDiskBytes)
                { error = "Not enough free disk space to expand the archive."; break; }

                string display = $"{archiveName} >> /{entry.Path.Replace('\\', '/')}";
                onEntry?.Invoke(display);

                var one = ExtractOne(sevenZip, archivePath, workDir, entry.Path, timeoutSec);
                if (one.WrongPassword)
                {
                    return new ArchiveResult(false, Array.Empty<ArchiveEntryFinding>(),
                        "Archive is encrypted", PasswordProtected: true);
                }
                if (!one.Ok || one.File == null) continue;

                try
                {
                    long actual = 0;
                    try { actual = new FileInfo(one.File).Length; } catch { }
                    budget -= actual;
                    if (budget < 0)
                    { error = "Corrupted data in archive detected, skipping."; break; }

                    var r = scanFn(one.File, display);
                    if (r.Verdict == Core.Verdict.Malware)
                    {
                        if (r.ArchiveFindings is { Count: > 0 } inner)
                        {
                            foreach (var f in inner)
                                findings.Add(new ArchiveEntryFinding(
                                    entry.Path + ChainSep + f.Entry,
                                    f.Detection, f.Source, f.Display, Direct: false));
                        }
                        else
                        {
                            findings.Add(new ArchiveEntryFinding(entry.Path, r.Detection ?? "unknown",
                                                                 r.Source, display, Direct: true));
                        }
                    }
                }
                finally
                {
                    try { File.Delete(one.File); } catch { }
                }
            }
        }
        catch (Exception ex) { error = ex.Message; }
        finally
        {
            try { Directory.Delete(workDir, true); } catch { }
        }

        return new ArchiveResult(findings.Count > 0, findings, error, Expanded: true);
    }

    private static (List<EntryInfo>? Entries, string? Error, bool HeaderEncrypted)
        ListEntries(string sevenZip, string archivePath, int timeoutSec)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = sevenZip,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            psi.ArgumentList.Add("l");
            psi.ArgumentList.Add("-slt");
            psi.ArgumentList.Add("-p");
            psi.ArgumentList.Add(archivePath);
            using var p = Process.Start(psi)!;
            var outTask = p.StandardOutput.ReadToEndAsync();
            var errTask = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(Math.Max(10, timeoutSec) * 1000))
            {
                try { p.Kill(true); } catch { }
                return (null, "Listing timeout", false);
            }
            string sout = outTask.GetAwaiter().GetResult();
            string serr = errTask.GetAwaiter().GetResult();
            if (p.ExitCode != 0)
            {
                bool enc = serr.IndexOf("Wrong password", StringComparison.OrdinalIgnoreCase) >= 0
                        || serr.IndexOf("encrypted", StringComparison.OrdinalIgnoreCase) >= 0;
                return (null, $"7z l rc={p.ExitCode}: {serr.Trim()}", enc);
            }

            var list = new List<EntryInfo>();
            string? path = null; long size = 0; bool isDir = false;
            void Flush()
            {
                if (path != null && !isDir && path.Length > 0) list.Add(new EntryInfo(path, size));
                path = null; size = 0; isDir = false;
            }

            bool inEntries = false;
            foreach (var raw in sout.Split('\n'))
            {
                var line = raw.TrimEnd('\r');
                if (!inEntries)
                {
                    if (line.StartsWith("----------", StringComparison.Ordinal)) inEntries = true;
                    continue;
                }
                if (line.Length == 0) { Flush(); continue; }
                int eq = line.IndexOf('=');
                if (eq < 1) continue;
                var key = line.Substring(0, eq).Trim();
                var val = line.Substring(eq + 1).Trim();
                if (key == "Path") { Flush(); path = val; }
                else if (key == "Size") long.TryParse(val, out size);
                else if (key == "Folder") isDir |= val == "+";
                else if (key == "Attributes") isDir |= val.StartsWith("D", StringComparison.OrdinalIgnoreCase);
            }
            Flush();
            return (list, null, false);
        }
        catch (Exception ex) { return (null, ex.Message, false); }
    }

    private readonly record struct SingleExtract(bool Ok, bool WrongPassword, string? File);

    private static SingleExtract ExtractOne(string sevenZip, string archivePath, string workDir,
                                            string entryPath, int timeoutSec)
    {
        var psi = new ProcessStartInfo
        {
            FileName = sevenZip,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        psi.ArgumentList.Add("e");
        psi.ArgumentList.Add(archivePath);
        psi.ArgumentList.Add($"-o{workDir}");
        psi.ArgumentList.Add("-y");
        psi.ArgumentList.Add("-snl");
        psi.ArgumentList.Add("-p");
        psi.ArgumentList.Add(entryPath);
        try
        {
            using var p = Process.Start(psi)!;
            var errTask = p.StandardError.ReadToEndAsync();
            _ = p.StandardOutput.ReadToEndAsync();
            if (!p.WaitForExit(Math.Max(10, timeoutSec) * 1000))
            {
                try { p.Kill(true); } catch { }
                return new SingleExtract(false, false, null);
            }
            string serr = "";
            try { serr = errTask.GetAwaiter().GetResult(); } catch { }
            if (p.ExitCode != 0)
            {
                bool wrongPw = serr.IndexOf("Wrong password", StringComparison.OrdinalIgnoreCase) >= 0
                            || serr.IndexOf("encrypted", StringComparison.OrdinalIgnoreCase) >= 0;
                return new SingleExtract(false, wrongPw, null);
            }
            var produced = Path.Combine(workDir, Path.GetFileName(entryPath));
            if (File.Exists(produced)) return new SingleExtract(true, false, produced);

            var any = Directory.EnumerateFiles(workDir).FirstOrDefault();
            return any != null ? new SingleExtract(true, false, any)
                               : new SingleExtract(false, false, null);
        }
        catch { return new SingleExtract(false, false, null); }
    }

    public ArchiveResult ScanArchive(string archivePath, Func<string, Core.DetectionResult> scanFn,
                                     int timeoutSec = 300, Action<string>? onEntry = null)
        => ScanArchive(archivePath,
            (tmp, _) => scanFn(tmp),
            timeoutSec, onEntry);

    private ArchiveResult? ScanWithLibrary(SevenZipLib lib, string archivePath, ArchiveScanFn scanFn,
                                           int timeoutSec, Action<string>? onEntry, string? displayName)
    {
        using var archive = lib.Open(archivePath);
        if (archive == null) return null;

        if (archive.HeaderEncrypted)
            return new ArchiveResult(false, Array.Empty<ArchiveEntryFinding>(),
                "Archive is encrypted", PasswordProtected: true);

        var entries = archive.List().Where(e => !e.IsDirectory).ToList();
        if (entries.Count == 0) return null;

        if (entries.Any(e => e.Encrypted))
            return new ArchiveResult(false, Array.Empty<ArchiveEntryFinding>(),
                "Archive is encrypted", PasswordProtected: true);

        var workRoot = Paths.WorkingDir;
        try { Directory.CreateDirectory(workRoot); }
        catch { workRoot = Path.GetTempPath(); }
        var workDir = Path.Combine(workRoot, $"arch-{Guid.NewGuid():N}");
        Directory.CreateDirectory(workDir);

        var findings = new List<ArchiveEntryFinding>();
        string archiveName = displayName ?? Path.GetFileName(archivePath);
        string? error = null;
        try
        {
            long budget = MaxExtractBytes;
            int scanned = 0;
            var deadline = Stopwatch.StartNew();

            foreach (var entry in entries)
            {
                if (++scanned > MaxExtractEntries)
                { error = "Too many entries in archive, truncated."; break; }
                if (deadline.Elapsed.TotalSeconds > timeoutSec)
                { error = "Archive scan timeout"; break; }
                if ((long)entry.Size > budget)
                { error = "Corrupted data in archive detected, skipping."; break; }
                long free = TryFreeSpace(workDir);
                if (free >= 0 && free < MinFreeDiskBytes)
                { error = "Not enough free disk space to expand the archive."; break; }

                string display = $"{archiveName} >> /{entry.Path.Replace('\\', '/')}";
                onEntry?.Invoke(display);

                var dest = Path.Combine(workDir, Path.GetFileName(entry.Path));
                if (string.IsNullOrEmpty(Path.GetFileName(entry.Path))) continue;
                if (!archive.ExtractTo(entry.Index, dest)) continue;

                try
                {
                    long actual = 0;
                    try { actual = new FileInfo(dest).Length; } catch { }
                    budget -= actual;
                    if (budget < 0)
                    { error = "Corrupted data in archive detected, skipping."; break; }

                    var r = scanFn(dest, display);
                    if (r.Verdict == Core.Verdict.Malware)
                    {
                        if (r.ArchiveFindings is { Count: > 0 } inner)
                        {
                            foreach (var f in inner)
                                findings.Add(new ArchiveEntryFinding(
                                    entry.Path + ChainSep + f.Entry,
                                    f.Detection, f.Source, f.Display, Direct: false));
                        }
                        else
                        {
                            findings.Add(new ArchiveEntryFinding(entry.Path, r.Detection ?? "unknown",
                                                                 r.Source, display, Direct: true));
                        }
                    }
                }
                finally { try { File.Delete(dest); } catch { } }
            }
        }
        catch (Exception ex) { error = ex.Message; }
        finally { try { Directory.Delete(workDir, true); } catch { } }

        return new ArchiveResult(findings.Count > 0, findings, error, Expanded: true);
    }

    public const string ChainSep = ">>";

    public bool RemoveEntryChain(string archivePath, IReadOnlyList<string> chain, int timeoutSec = 120)
    {
        if (chain.Count == 0) return false;
        if (chain.Count == 1) return RemoveEntries(archivePath, new[] { chain[0] }, timeoutSec);

        var sevenZip = _sevenZip ?? Paths.SevenZipExe;
        if (!File.Exists(sevenZip)) return false;

        var workRoot = Paths.WorkingDir;
        try { Directory.CreateDirectory(workRoot); } catch { workRoot = Path.GetTempPath(); }
        var workDir = Path.Combine(workRoot, $"fix-{Guid.NewGuid():N}");
        Directory.CreateDirectory(workDir);
        try
        {
            var ex = ExtractOne(sevenZip, archivePath, workDir, chain[0], timeoutSec);
            if (!ex.Ok || ex.File == null) return false;

            if (!RemoveEntryChain(ex.File, chain.Skip(1).ToList(), timeoutSec)) return false;

            var stage = Path.Combine(workDir, "stage");
            var dest = Path.Combine(stage, chain[0]);
            Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
            File.Move(ex.File, dest, overwrite: true);

            var psi = new ProcessStartInfo
            {
                FileName = sevenZip,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WorkingDirectory = stage,
            };
            psi.ArgumentList.Add("u");
            psi.ArgumentList.Add(archivePath);
            psi.ArgumentList.Add(chain[0]);
            psi.ArgumentList.Add("-y");
            using var p = Process.Start(psi)!;
            p.StandardError.ReadToEnd();
            p.StandardOutput.ReadToEnd();
            if (!p.WaitForExit(timeoutSec * 1000)) { try { p.Kill(true); } catch { } return false; }
            return p.ExitCode == 0;
        }
        catch { return false; }
        finally { try { Directory.Delete(workDir, true); } catch { } }
    }

    public bool RemoveEntries(string archivePath, IEnumerable<string> entryNames, int timeoutSec = 120)
    {
        var sevenZip = _sevenZip ?? Paths.SevenZipExe;
        if (!File.Exists(sevenZip)) return false;
        var psi = new ProcessStartInfo
        {
            FileName = sevenZip,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("d");
        psi.ArgumentList.Add(archivePath);
        foreach (var n in entryNames) psi.ArgumentList.Add(n);
        psi.ArgumentList.Add("-y");
        try
        {
            using var p = Process.Start(psi)!;
            p.StandardError.ReadToEnd();
            p.StandardOutput.ReadToEnd();
            if (!p.WaitForExit(timeoutSec * 1000)) { try { p.Kill(true); } catch { } return false; }
            return p.ExitCode == 0;
        }
        catch { return false; }
    }
}
