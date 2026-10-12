using System.Text.Json;

namespace Malward.BackupEngine;

public static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            EmitErr("brak komendy (status|estimate|backup|list|files|restore|delete|export|import|rollback|watch|selftest)");
            return 2;
        }
        var cmd = args[0].ToLowerInvariant();
        try
        {
            switch (cmd)
            {
                case "uninstall": return UninstallLegacyService();
                case "selftest":  return SelfTest();
                case "watch":     return WatchMode();
                case "install":   EmitErr("install: model on-demand nie używa usługi — pomijam."); return 0;

                case "boot-backup":  return EmitOk(BootSectorGuard.Backup());
                case "boot-status":  return EmitOk(BootSectorGuard.Status());
                case "boot-restore":
                {
                    bool all = HasFlag(args, "--all");
                    int? drive = int.TryParse(GetOpt(args, "--drive"), out var dv) ? dv : null;
                    return EmitOk(BootSectorGuard.Restore(drive, all));
                }
            }

            var config = BackupConfig.Load();
            using var runner = new BackupRunner(config);

            switch (cmd)
            {
                case "status":
                    return EmitOk(runner.StatusObject());

                case "estimate":
                    return EmitOk(runner.EstimateObject());

                case "backup":
                {
                    var trig = ParseTrigger(GetOpt(args, "--trigger") ?? "manual");
                    return RunBackupWithProgress(runner, trig, !HasFlag(args, "--no-pacing"));
                }

                case "list":
                    return EmitOk(new { snapshots = runner.ListObject() });

                case "files":
                {
                    if (args.Length < 2) { EmitErr("files: brak snapId"); return 2; }
                    var files = runner.FilesObject(Guid.Parse(args[1]));
                    return EmitOk(new { snap_id = args[1], files });
                }

                case "restore":
                {
                    if (args.Length < 2) { EmitErr("restore: brak snapId"); return 2; }
                    var paths = ReadPathsFile(GetOpt(args, "--paths-file"));
                    var target = GetOpt(args, "--target");
                    var (r, f) = runner.Restore(Guid.Parse(args[1]), paths, target);
                    return EmitOk(new { restored = r, failed = f });
                }

                case "delete":
                {
                    if (args.Length < 2) { EmitErr("delete: brak snapId"); return 2; }
                    var ok = runner.Delete(Guid.Parse(args[1]));
                    return EmitOk(new { deleted = ok });
                }

                case "export":
                {
                    if (args.Length < 3) { EmitErr("export: użycie export <snapId> <outFile>"); return 2; }
                    runner.Export(Guid.Parse(args[1]), args[2]);
                    return EmitOk(new { ok = true, path = args[2] });
                }

                case "import":
                {
                    if (args.Length < 2) { EmitErr("import: brak ścieżki pliku"); return 2; }
                    var n = runner.Import(args[1]);
                    return EmitOk(new { imported = n });
                }

                case "rollback":
                {
                    var paths = ReadPathsFile(GetOpt(args, "--paths-file")) ?? Array.Empty<string>();
                    long sinceUnix = long.TryParse(GetOpt(args, "--since"), out var sv)
                        ? sv : DateTimeOffset.UtcNow.AddMinutes(-30).ToUnixTimeSeconds();
                    var rep = runner.Rollback(paths, DateTimeOffset.FromUnixTimeSeconds(sinceUnix));
                    return EmitOk(new { restored = rep.Restored, from_bkf = rep.FromBkf, from_vss = rep.FromVss, failed = rep.Failed });
                }

                default:
                    EmitErr($"nieznana komenda: {cmd}");
                    return 2;
            }
        }
        catch (Exception ex)
        {
            EmitErr($"{ex.GetType().Name}: {ex.Message}");
            return 1;
        }
    }

    private static BkfFormat.Trigger ParseTrigger(string s) => s.ToLowerInvariant() switch
    {
        "schedule" => BkfFormat.Trigger.Schedule,
        "fswatch"  => BkfFormat.Trigger.FsWatch,
        "prerollback" => BkfFormat.Trigger.PreRollback,
        _ => BkfFormat.Trigger.Manual,
    };

    private static string? GetOpt(string[] args, string name)
    {
        for (int i = 0; i < args.Length - 1; i++)
            if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
                return args[i + 1];
        return null;
    }

    private static bool HasFlag(string[] args, string name)
        => args.Any(a => string.Equals(a, name, StringComparison.OrdinalIgnoreCase));

    private static string[]? ReadPathsFile(string? file)
    {
        if (string.IsNullOrEmpty(file) || !File.Exists(file)) return null;
        return File.ReadAllLines(file)
                   .Select(l => l.Trim())
                   .Where(l => l.Length > 0)
                   .ToArray();
    }

    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = false };

    public static string CancelFlagPath => Path.Combine(
        Path.GetDirectoryName(BackupConfig.DefaultConfigPath)!, "backup-cancel");

    private static int RunBackupWithProgress(BackupRunner runner, BkfFormat.Trigger trigger, bool pace)
    {
        try { File.Delete(CancelFlagPath); } catch { }

        if (pace) BackupPacing.EnterBackgroundMode();

        using var cts = new CancellationTokenSource();
        using var watch = new Timer(_ =>
        {
            try { if (File.Exists(CancelFlagPath)) cts.Cancel(); } catch { }
        }, null, 500, 500);

        long lastReport = 0;
        void Report(BackupProgress bp)
        {
            long now = Environment.TickCount64;
            bool last = bp.TotalFiles > 0 && bp.DoneFiles >= bp.TotalFiles;
            if (!last && now - lastReport < 250) return;
            lastReport = now;
            Console.Out.WriteLine(
                $"BACKUP-PROGRESS:{bp.DoneFiles}/{bp.TotalFiles}:{bp.DoneBytes}/{bp.TotalBytes}");
            Console.Out.Flush();
        }

        try
        {
            var id = runner.DoBackup(trigger, Report, cts.Token);
            bool cancelled = cts.IsCancellationRequested;
            return EmitOk(new
            {
                snap_id = id.ToString(),
                cancelled,
                empty = !cancelled && id == Guid.Empty,
            });
        }
        finally
        {
            if (pace) BackupPacing.LeaveBackgroundMode();
            try { File.Delete(CancelFlagPath); } catch { }
        }
    }

    private static int EmitOk(object result)
    {
        Console.Out.WriteLine(JsonSerializer.Serialize(new { ok = true, result }, JsonOpts));
        return 0;
    }

    private static void EmitErr(string error)
    {
        Console.Out.WriteLine(JsonSerializer.Serialize(new { ok = false, error }, JsonOpts));
    }

    private static int WatchMode()
    {
        var config = BackupConfig.Load();
        if (!config.OnFileChange)
        {
            Log.Info("Watch", "on_file_change=false — watch mode inactive, exit.");
            return 0;
        }
        using var mutex = TryAcquireSingleton(out bool acquired);
        if (!acquired) { Log.Warn("Watch", "Another watch instance is already running — exit."); return 0; }

        Log.Info("Watch", "FSWatch start (file-change snapshots)…");
        var watcher = new FileWatcher(config);
        watcher.Start();
        var stop = new ManualResetEventSlim(false);
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Set(); };

        while (!stop.IsSet)
        {
            try
            {
                var ready = watcher.DrainReady();
                if (ready.Count > 0)
                {
                    Guid id;
                    using (var runner = new BackupRunner(config))
                    {
                        id = runner.DoBackupPaths(ready, BkfFormat.Trigger.FsWatch);
                        foreach (var p in ready) watcher.MarkBackupDone(p);
                    }
                    if (id != Guid.Empty)
                        Log.Info("Watch", $"FsWatch snapshot {id} from {ready.Count} candidates");
                    else
                        Log.Debug("Watch", $"No snapshot — {ready.Count} candidates but 0 files to write.");

                    TrimWorkingSet();
                }
            }
            catch (Exception ex) { Log.Warn("Watch", ex.Message); }
            stop.Wait(TimeSpan.FromSeconds(10));
        }
        watcher.Dispose();
        return 0;
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern bool SetProcessWorkingSetSize(IntPtr proc, IntPtr min, IntPtr max);

    private static void TrimWorkingSet()
    {
        try
        {
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, blocking: true, compacting: true);
            GC.WaitForPendingFinalizers();
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, blocking: true, compacting: true);
            SetProcessWorkingSetSize(System.Diagnostics.Process.GetCurrentProcess().Handle,
                new IntPtr(-1), new IntPtr(-1));
        }
        catch { }
    }

    private static Mutex? TryAcquireSingleton(out bool acquired)
    {
        try
        {
            var m = new Mutex(true, "Global\\MalwardBackupEngine-Watch", out acquired);
            return m;
        }
        catch (UnauthorizedAccessException) { acquired = false; return null; }
    }

    private static int UninstallLegacyService()
    {
        var psi = new System.Diagnostics.ProcessStartInfo("sc.exe", "delete MalwardBackupEngine")
        { UseShellExecute = false, CreateNoWindow = true };
        try { var p = System.Diagnostics.Process.Start(psi); p?.WaitForExit(8000); } catch { }
        EmitOk(new { ok = true });
        return 0;
    }

    private static int SelfTest()
    {
        var temp = Path.Combine(Path.GetTempPath(), "mwbk-selftest-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(temp);
        var bkfPath = Path.Combine(temp, "t.bkf");
        var keyPath = Path.Combine(temp, "t.key");
        int passed = 0, failed = 0;
        void Check(string n, bool ok) { Console.Error.WriteLine((ok ? "[OK]   " : "[FAIL] ") + n); if (ok) passed++; else failed++; }
        try
        {
            var crypto = CryptoEnvelope.LoadOrCreate(keyPath);

            var srcDir = Path.Combine(temp, "src"); Directory.CreateDirectory(srcDir);
            var f1 = Path.Combine(srcDir, "a.txt"); File.WriteAllText(f1, "Hello ąęł");
            var f2 = Path.Combine(srcDir, "b.bin"); File.WriteAllBytes(f2, System.Security.Cryptography.RandomNumberGenerator.GetBytes(50000));
            var f3 = Path.Combine(srcDir, "c.json"); File.WriteAllText(f3, "{\"x\":1}");

            foreach (var mode in new[] { CompressionMode.None, CompressionMode.Deflate, CompressionMode.Brotli })
            {
                using var bkf = new BkfFile(bkfPath + (byte)mode, crypto);
                bkf.Open();
                var id = bkf.AppendSnapshotStreaming(new[] { f1, f2, f3 }, BkfFormat.Trigger.Manual, compression: mode);
                var snap = bkf.ReadSnapshot(id);
                int match = 0;
                foreach (var fe in snap.Files)
                {
                    var content = bkf.ReadFileContent(snap, fe);
                    var orig = File.ReadAllBytes(fe.Path);
                    if (content.SequenceEqual(orig)) match++;
                }
                Check($"roundtrip [{mode}] 3/3 content match", match == 3);
            }

            using (var bkf = new BkfFile(bkfPath + "X", crypto))
            {
                bkf.Open();
                var s1 = bkf.AppendSnapshotStreaming(new[] { f1 }, BkfFormat.Trigger.Manual);
                var s2 = bkf.AppendSnapshotStreaming(new[] { f2 }, BkfFormat.Trigger.Manual);
                Check("2 snapshoty", bkf.SnapshotCount == 2);
                var exp = Path.Combine(temp, "exp.mwbk");
                bkf.ExportSnapshot(s1, exp);
                Check("export plik istnieje", File.Exists(exp));
                Check("delete s1", bkf.DeleteSnapshot(s1));
                Check("po delete 1 snapshot", bkf.SnapshotCount == 1);
                var imp = bkf.ImportFromFile(exp);
                Check("import 1", imp == 1 && bkf.SnapshotCount == 2);

                var snap = bkf.ReadSnapshot(s1);
                var c = bkf.ReadFileContent(snap, snap.Files[0]);
                Check("restore zaimportowanego == oryginał", c.SequenceEqual(File.ReadAllBytes(f1)));
            }
        }
        catch (Exception ex) { Console.Error.WriteLine($"EXC: {ex}"); failed++; }
        finally { try { Directory.Delete(temp, true); } catch { } }
        Console.Error.WriteLine($"=== {passed} passed, {failed} failed ===");
        return failed == 0 ? 0 : 1;
    }
}
