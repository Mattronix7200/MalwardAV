using System.Diagnostics;
using System.Security.AccessControl;
using System.ServiceProcess;
using System.Text;
using System.Windows.Forms;

namespace Malward.Updater;

internal static class Program
{
    private const string LogName = "update.log";

    private static string _logPath = "";

    private static ProgressForm? _ui;
    private static int _rc = 1;
    private static bool _english;

    private static string L(string pl, string en) => _english ? en : pl;

    private static bool ReadEnglish()
    {
        try
        {
            var path = Path.Combine(DataDir(), "data", "gui-settings.json");
            if (!File.Exists(path)) return false;
            using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(path));
            return doc.RootElement.TryGetProperty("lang", out var l)
                && string.Equals(l.GetString(), "en", StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    [STAThread]
    private static int Main(string[] args)
    {
        var opts = Options.Parse(args);
        _logPath = Path.Combine(DataDir(), "logs", LogName);
        try { Directory.CreateDirectory(Path.GetDirectoryName(_logPath)!); } catch { }

        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        _english = ReadEnglish();

        if (opts == null)
        {
            MessageBox.Show(
                L("Użycie: mwupdate --staging <katalog> --install <katalog> [--wait-pid <pid>] [--relaunch]",
                  "Usage: mwupdate --staging <dir> --install <dir> [--wait-pid <pid>] [--relaunch]"),
                L("Malward — aktualizacja", "Malward — update"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 2;
        }

        _ui = new ProgressForm(_english);
        _ui.Shown += (_, _) => Task.Run(() =>
        {
            try { _rc = Run(opts); }
            catch (Exception ex) { Log($"FATAL: {ex}"); _rc = 1; }
            _ui.Finish(_rc == 0,
                _rc == 0 ? L("Program zostanie uruchomiony ponownie.", "The program will now restart.")
                         : L($"Szczegóły w dzienniku aktualizacji:\n{_logPath}", $"Details in the update log:\n{_logPath}"));
        });
        Application.Run(_ui);
        return _rc;
    }

    private static void Step(string pl, string en, int done = -1, int total = -1, bool log = true)
    {
        if (log) Log(en);
        try { _ui?.Report(_english ? en : pl, done, total); } catch { }
    }

    private static int Run(Options opts)
    {
        Log($"=== Update: {opts.Staging} -> {opts.Install} ===");
        try
        {
            if (!Directory.Exists(opts.Staging)) { Log("ERROR: the new-version directory does not exist."); return 3; }
            if (!Directory.Exists(opts.Install)) { Log("ERROR: the install directory does not exist."); return 4; }

            var self = Path.GetDirectoryName(Environment.ProcessPath ?? "") ?? "";
            if (SamePath(self, opts.Install))
            {
                Log("ERROR: the updater is running from the directory it is supposed to replace. Run it from the new-version directory.");
                return 5;
            }

            Step("Czekam na zamknięcie programu…", "Waiting for the program to close…");
            WaitForExit(opts.WaitPid);

            Step("Zatrzymuję usługi ochrony…", "Stopping protection services…");
            var stopped = StopServices();
            KillLeftovers();

            Step("Odblokowuję katalog programu…", "Unlocking the program folder…");
            if (!UnlockInstallFolder(opts.Install))
            {
                // Kopiowanie do zablokowanego katalogu konczy sie sciana identycznych
                // "Access to the path is denied" i podmiana polowy plikow, gdyby czesc
                // jednak przeszla. Lepiej nie zaczynac.
                Log("=== Aborted: the install folder is not writable, nothing was changed ===");
                StartServices(stopped);
                return 3;
            }

            Step("Kopiuję pliki…", "Copying files…");
            var (copied, failed) = CopyTree(opts.Staging, opts.Install);
            RetireRenamedComponents(opts.Install);
            Log($"Files copied: {copied}, failed: {failed.Count}");
            foreach (var f in failed) Log($"  NOT WRITTEN: {f}");

            Step("Uruchamiam usługi ochrony…", "Starting protection services…");
            StartServices(stopped);

            var version = WriteVersionFile(opts.Install, opts.Staging);
            WriteOutcome(failed, version);

            if (opts.Relaunch) Relaunch(opts.Install);

            Step("Sprzątam…", "Cleaning up…");
            CleanStaging(opts.Staging);

            Log(failed.Count == 0 ? "=== Finished successfully ===" : "=== Finished with errors ===");
            return failed.Count == 0 ? 0 : 6;
        }
        catch (Exception ex)
        {
            Log($"CRITICAL ERROR: {ex}");

            try { StartServices(KnownServices.ToList()); } catch { }
            return 1;
        }
    }

    private sealed record Options(string Staging, string Install, int WaitPid, bool Relaunch)
    {
        public static Options? Parse(string[] args)
        {
            string staging = "", install = "";
            int pid = 0;
            bool relaunch = false;
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i].ToLowerInvariant())
                {
                    case "--staging" when i + 1 < args.Length: staging = args[++i]; break;
                    case "--install" when i + 1 < args.Length: install = args[++i]; break;
                    case "--wait-pid" when i + 1 < args.Length: int.TryParse(args[++i], out pid); break;
                    case "--relaunch": relaunch = true; break;
                }
            }
            if (staging.Length == 0 || install.Length == 0) return null;
            return new Options(Path.GetFullPath(staging), Path.GetFullPath(install), pid, relaunch);
        }
    }

    private static void WaitForExit(int pid)
    {
        if (pid <= 0) return;
        try
        {
            using var p = Process.GetProcessById(pid);
            Log($"Waiting for the interface to close (PID {pid})…");
            if (!p.WaitForExit(30_000))
            {
                Log("The interface did not close within 30 s — terminating it.");
                try { p.Kill(entireProcessTree: true); p.WaitForExit(5_000); } catch { }
            }
        }
        catch (ArgumentException) {  }
        catch (Exception ex) { Log($"Waiting for the interface: {ex.Message}"); }
    }

    private static readonly string[] KnownServices =
        { "MalwardResidentShield", "MalwardNetworkScanner", "MalwardBackupEngine" };

    private static List<string> StopServices()
    {
        var stopped = new List<string>();
        foreach (var name in KnownServices)
        {
            try
            {
                using var sc = new ServiceController(name);
                var status = sc.Status;
                if (status is ServiceControllerStatus.Stopped or ServiceControllerStatus.StopPending)
                {
                    Log($"Service {name}: already stopped.");
                    continue;
                }
                Log($"Stopping service {name}…");
                sc.Stop();
                sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(45));

                stopped.Add(name);
            }
            catch (InvalidOperationException) {  }
            catch (Exception ex) { Log($"Service {name}: {ex.Message}"); }
        }
        return stopped;
    }

    private static void StartServices(List<string> names)
    {
        foreach (var name in names)
        {
            try
            {
                using var sc = new ServiceController(name);
                if (sc.Status == ServiceControllerStatus.Running) continue;
                Log($"Starting service {name}…");
                sc.Start();
                sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(45));
            }
            catch (InvalidOperationException) {  }
            catch (Exception ex) { Log($"Failed to start {name}: {ex.Message}"); }
        }
    }

    private static void KillLeftovers()
    {
        string[] names = { "Malward", "malscan", "mwshield", "rsmonitor", "netmonitor", "bkmonitor", "heurscanner", "mla_scanner" };
        int self = Environment.ProcessId;
        foreach (var n in names)
        {
            Process[] found;
            try { found = Process.GetProcessesByName(n); } catch { continue; }
            foreach (var p in found)
            {
                try
                {
                    if (p.Id == self) continue;
                    Log($"Terminating process {n} (PID {p.Id})…");
                    p.Kill(entireProcessTree: true);
                    p.WaitForExit(10_000);
                }
                catch (Exception ex) { Log($"Process {n}: {ex.Message}"); }
                finally { p.Dispose(); }
            }
        }
    }

    private static readonly string[] RetiredFiles =
    {
        "rsmonitor.exe", "rsmonitor.dll", "rsmonitor.pdb",
        "rsmonitor.deps.json", "rsmonitor.runtimeconfig.json",
    };

    private static void RetireRenamedComponents(string install)
    {
        if (!File.Exists(Path.Combine(install, "mwshield.exe")))
        {
            Log("The new shield file was not created — old files are left untouched.");
            return;
        }

        foreach (var nazwa in RetiredFiles)
        {
            var p = Path.Combine(install, nazwa);
            if (!File.Exists(p)) continue;
            try
            {
                File.SetAttributes(p, FileAttributes.Normal);
                File.Delete(p);
                Log($"Removed renamed-component file: {nazwa}");
            }
            catch (Exception ex)
            {
                try
                {
                    File.Move(p, p + ".old-" + Environment.ProcessId, overwrite: true);
                    Log($"Moved aside locked renamed-component file: {nazwa}");
                }
                catch { Log($"Failed to remove {nazwa}: {ex.Message}"); }
            }
        }
    }

    private static readonly string[] NeverCopy = { "update.log" };

    private static (int Copied, List<string> Failed) CopyTree(string from, string to)
    {
        int copied = 0;
        var failed = new List<string>();

        var all = Directory.EnumerateFiles(from, "*", SearchOption.AllDirectories).ToList();
        int index = 0;
        foreach (var src in all)
        {
            index++;
            var rel = Path.GetRelativePath(from, src);
            Step("Kopiuję pliki…", "Copying files…", index, all.Count, log: false);
            if (NeverCopy.Contains(Path.GetFileName(rel), StringComparer.OrdinalIgnoreCase)) continue;

            var dst = Path.Combine(to, rel);
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(dst)!);
                bool existed = File.Exists(dst);

                if (existed && SameContent(src, dst)) continue;

                if (existed)
                {
                    try { File.SetAttributes(dst, FileAttributes.Normal); } catch { }
                    try
                    {
                        File.Copy(src, dst, overwrite: true);
                        copied++;
                        continue;
                    }

                    catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                    {
                        var aside = dst + ".old-" + Environment.ProcessId;
                        try { File.Move(dst, aside, overwrite: true); }
                        catch (Exception ex) { failed.Add($"{rel}: {ex.Message}"); continue; }
                    }
                }

                File.Copy(src, dst, overwrite: true);

                if (!existed) ResetToInherited(dst);
                copied++;
            }
            catch (Exception ex) { failed.Add($"{rel}: {ex.Message}"); }
        }

        return (copied, failed);
    }

    /// <summary>Takes the guard off the install folder. Returns false when the folder is still read-only.</summary>
    /// <remarks>
    /// The previous version ran three icacls calls, ignored every exit code and then logged
    /// "Install directory lock removed" unconditionally. When the guard stayed on, the log
    /// claimed success and the copy that followed failed on all 28 files with a bare
    /// "Access to the path is denied", with nothing tying the two together.
    ///
    /// The deciding test is not what icacls returns but whether the folder can actually be
    /// written to, so that is what gets checked - and the guard marker is only dropped once
    /// the write succeeds, otherwise the service and the updater disagree about reality.
    /// </remarks>
    private static bool UnlockInstallFolder(string dir)
    {
        try
        {
            if (!Directory.Exists(dir)) return true;
            if (CanWriteInto(dir)) return true;

            // Wlasciciel ma WRITE_DAC niezaleznie od listy uprawnien, wiec przejecie wlasnosci
            // musi byc pierwsze - bez tego /reset nie ma prawa zmienic ACL.
            var kroki = new[]
            {
                $"\"{dir}\" /setowner *S-1-5-32-544 /T /C /Q",
                $"\"{dir}\" /remove:d *S-1-1-0 /T /C /Q",
                $"\"{dir}\" /grant *S-1-5-32-544:(OI)(CI)(F) /T /C /Q",
                $"\"{dir}\" /grant *S-1-5-18:(OI)(CI)(F) /T /C /Q",
                $"\"{dir}\" /reset /T /C /Q",
                $"\"{dir}\" /inheritance:e",
            };
            foreach (var krok in kroki)
            {
                var (rc, output) = Icacls(krok);
                if (rc != 0)
                    Log($"  icacls rc={rc}: {Trim(output)}");
            }

            if (!CanWriteInto(dir))
            {
                Log("Failed to remove the install directory lock — the folder is still read-only.");
                Log("  Nothing was copied. Stop the Malward service, run the update again, or");
                Log("  clear the lock by hand:");
                Log($"  icacls \"{dir}\" /setowner *S-1-5-32-544 /T /C");
                Log($"  icacls \"{dir}\" /remove:d *S-1-1-0 /T /C");
                Log($"  icacls \"{dir}\" /reset /T /C");
                return false;
            }

            var marker = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Malward", "data", "folder-guard.applied");
            try { if (File.Exists(marker)) File.Delete(marker); } catch { }

            Log("Install directory lock removed (the service will re-apply it at startup).");
            return true;
        }
        catch (Exception ex)
        {
            Log($"Failed to remove the directory lock: {ex.Message}");
            return false;
        }
    }

    /// <summary>Writes and deletes a probe file. The only check that answers the question we have.</summary>
    private static bool CanWriteInto(string dir)
    {
        var probe = Path.Combine(dir, ".malward-update-probe");
        try
        {
            File.WriteAllBytes(probe, new byte[] { 0 });
            File.Delete(probe);
            return true;
        }
        catch
        {
            try { if (File.Exists(probe)) File.Delete(probe); } catch { }
            return false;
        }
    }

    private static string Trim(string text)
    {
        text = (text ?? "").Replace("\r", " ").Replace("\n", " ").Trim();
        return text.Length <= 160 ? text : text[..160] + "...";
    }

    private static (int rc, string output) Icacls(string args)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("icacls", args)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });
            if (p == null) return (-1, "failed to start icacls.exe");
            string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            if (!p.WaitForExit(30000)) { try { p.Kill(); } catch { } return (-1, "icacls: timeout"); }
            return (p.ExitCode, output);
        }
        catch (Exception ex) { return (-1, ex.Message); }
    }

    private static string? WriteVersionFile(string install, string staging)
    {
        string? version = null;
        try
        {
            var exe = Path.Combine(staging, "Malward.exe");
            if (!File.Exists(exe)) exe = Path.Combine(install, "Malward.exe");
            if (File.Exists(exe))
            {
                var vi = FileVersionInfo.GetVersionInfo(exe);
                version = (vi.ProductVersion ?? vi.FileVersion ?? "").Split('+')[0].Trim();
            }
        }
        catch (Exception ex) { Log($"Version: {ex.Message}"); }
        if (string.IsNullOrEmpty(version)) return null;
        try
        {
            File.WriteAllText(Path.Combine(install, "version.txt"), version + Environment.NewLine, new UTF8Encoding(false));
            Log($"Installed version: {version}");
        }
        catch (Exception ex) { Log($"version.txt: {ex.Message}"); }
        return version;
    }

    private static void WriteOutcome(List<string> failed, string? version)
    {
        try
        {
            var path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Malward", "data", "update-outcome.txt");
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var done = Path.Combine(Path.GetDirectoryName(path)!, "update-done.txt");
            if (failed.Count == 0)
            {
                if (File.Exists(path)) File.Delete(path);

                File.WriteAllText(done, version ?? "", new UTF8Encoding(false));
                return;
            }
            try { if (File.Exists(done)) File.Delete(done); } catch { }

            var lines = new List<string> { $"NIE ZAPISANO PLIKÓW: {failed.Count}" };
            lines.AddRange(failed.Take(20));
            if (failed.Count > 20) lines.Add($"... i {failed.Count - 20} więcej (szczegóły w update.log)");
            File.WriteAllText(path, string.Join(Environment.NewLine, lines));
        }
        catch { }
    }

    private static void ResetToInherited(string path)
    {
        try
        {
            var fi = new FileInfo(path);
            var sec = fi.GetAccessControl();
            sec.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);
            foreach (FileSystemAccessRule r in sec.GetAccessRules(true, false, typeof(System.Security.Principal.NTAccount)))
                sec.RemoveAccessRule(r);
            fi.SetAccessControl(sec);
        }
        catch (Exception ex) { Log($"Permissions {Path.GetFileName(path)}: {ex.Message}"); }
    }

    private static bool SameContent(string a, string b)
    {
        try
        {
            var fa = new FileInfo(a);
            var fb = new FileInfo(b);
            if (fa.Length != fb.Length) return false;
            using var sa = File.OpenRead(a);
            using var sb = File.OpenRead(b);
            var ha = System.Security.Cryptography.SHA256.HashData(sa);
            var hb = System.Security.Cryptography.SHA256.HashData(sb);
            return ha.AsSpan().SequenceEqual(hb);
        }
        catch { return false; }
    }

    private static void Relaunch(string install)
    {
        var exe = Path.Combine(install, "Malward.exe");
        if (!File.Exists(exe)) { Log("Malward.exe not found — skipping relaunch."); return; }
        try
        {
            Log("Starting the interface…");
            var psi = new ProcessStartInfo(exe) { UseShellExecute = true, WorkingDirectory = install };
            Process.Start(psi);
        }
        catch (Exception ex) { Log($"Failed to start the interface: {ex.Message}"); }
    }

    private static void CleanStaging(string staging)
    {
        try { File.WriteAllText(Path.Combine(DataDir(), "update", "cleanup.txt"), staging); }
        catch (Exception ex) { Log($"Cleanup marker: {ex.Message}"); }
    }

    private static string DataDir() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Malward");

    private static bool SamePath(string a, string b)
    {
        try
        {
            return string.Equals(
                Path.GetFullPath(a).TrimEnd('\\'), Path.GetFullPath(b).TrimEnd('\\'),
                StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    private static void Log(string message)
    {
        var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {message}";
        Console.WriteLine(line);
        try { File.AppendAllText(_logPath, line + Environment.NewLine, Encoding.UTF8); } catch { }
    }
}
