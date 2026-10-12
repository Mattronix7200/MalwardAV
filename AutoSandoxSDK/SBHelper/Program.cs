using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;
using DiscUtils.Iso9660;

namespace MalwardSandbox
{
    internal static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            Console.Title = "Malward Sandbox Controller";
            Console.WriteLine("====================================================");
            Console.WriteLine("             MALWARD SANDBOX HELPER v3.2            ");
            Console.WriteLine("====================================================");

            var opt = SandboxOptions.Parse(args);

            string? binRoot = ResolveBinRoot(opt.BinDir);
            if (binRoot == null)
            {
                Fail("Nie odnaleziono katalogu sandboxa (qemu\\qemu-system-x86_64.exe). " +
                     "Podaj --bin <ścieżka do folderu bin>.", opt.Interactive);
                return 2;
            }

            string qemuExe   = Path.Combine(binRoot, "qemu", "qemu-system-x86_64.exe");
            string diskDir   = Path.Combine(binRoot, "disk");
            string sharedDir = Path.Combine(binRoot, "shared");
            string qcow2Path = Path.Combine(diskDir, "default.qcow2");
            string seed7z    = Path.Combine(sharedDir, "default.7z");
            string isoPath   = Path.Combine(Path.GetTempPath(), $"mw-sbox-{Guid.NewGuid():N}.iso");

            string? sevenZip = ResolveSevenZip(binRoot, opt.SevenZip);

            Console.WriteLine($"[INFO] bin:    {binRoot}");
            Console.WriteLine($"[INFO] qemu:   {qemuExe}");
            Console.WriteLine($"[INFO] 7-Zip:  {sevenZip ?? "(NIE ZNALEZIONO)"}");
            Console.WriteLine($"[INFO] seed:   {seed7z}");

            if (!File.Exists(qemuExe)) { Fail($"Brak QEMU: {qemuExe}", opt.Interactive); return 2; }
            if (sevenZip == null || !File.Exists(sevenZip))
            { Fail("Nie znaleziono 7z.exe — podaj --sevenzip <ścieżka>.", opt.Interactive); return 2; }
            if (!File.Exists(seed7z)) { Fail($"Brak obrazu bazowego: {seed7z}", opt.Interactive); return 2; }

            string? targetFile = opt.ExePath;
            if (string.IsNullOrWhiteSpace(targetFile))
            {
                Console.WriteLine("\n[KROK 1] Przeciągnij plik EXE do piaskownicy i naciśnij Enter:");
                targetFile = Console.ReadLine()?.Replace("\"", "").Trim();
            }
            if (string.IsNullOrWhiteSpace(targetFile) || !File.Exists(targetFile))
            { Fail("Plik źródłowy do uruchomienia nie istnieje.", opt.Interactive); return 2; }

            Process? qemuProc = null;
            HelpOverlay? overlay = null;
            try
            {
                WriteStatus(opt.StatusPath, "extract", "Przywracanie czystego obrazu systemu…");
                Console.WriteLine("\n[KROK 2] Przywracanie czystego obrazu systemu (qcow2)…");
                Directory.CreateDirectory(diskDir);
                var zInfo = new ProcessStartInfo
                {
                    FileName = sevenZip,
                    Arguments = $"x \"{seed7z}\" -o\"{diskDir}\" -y",
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true,
                };
                Process.Start(zInfo)?.WaitForExit();
                if (!File.Exists(qcow2Path))
                    throw new Exception("7-Zip nie wypakował default.qcow2!");

                WriteStatus(opt.StatusPath, "iso", "Przygotowywanie pliku do uruchomienia…");
                Console.WriteLine("[KROK 3] Generowanie obrazu ISO z plikiem…");
                var builder = new CDBuilder { VolumeIdentifier = "MALWARD_SBOX", UseJoliet = true };
                builder.AddFile("payload.exe", File.ReadAllBytes(targetFile));
                builder.Build(isoPath);

                bool autoAccel = opt.Accel.Equals("auto", StringComparison.OrdinalIgnoreCase);
                string firstAccel = autoAccel ? "whpx" : opt.Accel;

                WriteStatus(opt.StatusPath, "starting", "Uruchamianie maszyny…");
                Console.WriteLine("[KROK 4] Uruchamianie maszyny…");
                qemuProc = LaunchQemu(qemuExe, binRoot, opt, qcow2Path, isoPath, firstAccel);

                if (autoAccel && WaitedAndExited(qemuProc, 6000))
                {
                    Console.WriteLine("[!] Akcelerator sprzętowy (WHPX) niedostępny lub zablokowany " +
                                      "(np. w maszynie wirtualnej). Przełączam na tryb programowy (TCG)…");
                    qemuProc = LaunchQemu(qemuExe, binRoot, opt, qcow2Path, isoPath, "tcg");
                }

                Thread.Sleep(2500);
                ApplyShieldIcon(qemuProc);
                overlay = HelpOverlay.Launch(qemuProc);

                WriteStatus(opt.StatusPath, "running", "Maszyna uruchomiona.");
                Console.WriteLine("\n>>> SANDBOX AKTYWNY. Zamknij okno maszyny, aby zakończyć sesję.");
                qemuProc.WaitForExit();
            }
            catch (Exception ex)
            {
                WriteStatus(opt.StatusPath, "error", ex.Message);
                Console.WriteLine($"\nBŁĄD: {ex.Message}");
            }
            finally
            {
                overlay?.Close();

                Console.WriteLine("\n[KROK 5] Czyszczenie plików sesji…");
                Cleanup(qcow2Path, isoPath);
            }

            Console.WriteLine("Sesja zakończona.");
            if (opt.Interactive)
            {
                Console.WriteLine("\nNaciśnij dowolny klawisz, aby wyjść.");
                Console.ReadKey();
            }
            return 0;
        }

        static Process LaunchQemu(string qemuExe, string binRoot, SandboxOptions opt,
                                  string qcow2Path, string isoPath, string accel)
        {
            string args = BuildQemuArgs(opt, qcow2Path, isoPath, accel);
            Console.WriteLine($"[CMD] ({accel}) {qemuExe} {args}");
            var p = new Process();
            p.StartInfo.FileName = qemuExe;
            p.StartInfo.Arguments = args;
            p.StartInfo.WorkingDirectory = binRoot;
            p.Start();
            return p;
        }

        static bool WaitedAndExited(Process p, int ms)
        {
            try { return p.WaitForExit(ms); }
            catch { return false; }
        }

        static string BuildQemuArgs(SandboxOptions o, string qcow2Path, string isoPath, string accel)
        {
            int threads = o.HyperThreading ? Math.Max(1, o.Threads) : 1;
            int cores   = Math.Max(1, o.Cores);
            int total   = cores * threads;

            string cpu = o.Cpu;
            if (cpu.Equals("host", StringComparison.OrdinalIgnoreCase)) cpu = "qemu64";

            string accelArg = accel.Equals("tcg", StringComparison.OrdinalIgnoreCase)
                ? "-accel tcg,thread=multi"
                : "-accel whpx";

            var sb = new List<string>
            {
                $"-m {o.MemoryGb}G",
                $"-smp {total},cores={cores},threads={threads}",
                "-machine q35",
                $"-cpu {cpu}",
                accelArg,
                "-name \"Malward Sandbox\"",
                "-display gtk,show-menubar=off",
                $"-drive file=\"{qcow2Path}\",format=qcow2,index=0,media=disk",
                $"-cdrom \"{isoPath}\"",
                "-vga vmware",
                "-device qemu-xhci",
                "-device usb-tablet",
                "-rtc base=localtime",
            };

            if (!o.Network)
            {
                sb.Add("-net none");
            }
            else
            {
                sb.Add("-net nic,model=e1000");
                sb.Add(o.NatRestrict ? "-net user,restrict=on" : "-net user");
            }

            if (o.Fullscreen) sb.Add("-full-screen");

            return string.Join(" ", sb);
        }

        static string? ResolveBinRoot(string? explicitBin)
        {
            var candidates = new List<string>();
            if (!string.IsNullOrWhiteSpace(explicitBin)) candidates.Add(explicitBin!);

            string baseDir = AppContext.BaseDirectory;
            candidates.Add(baseDir);
            candidates.Add(Path.Combine(baseDir, "bin"));

            var dir = new DirectoryInfo(baseDir);
            while (dir != null)
            {
                candidates.Add(dir.FullName);
                candidates.Add(Path.Combine(dir.FullName, "bin"));
                dir = dir.Parent;
            }

            foreach (var c in candidates)
            {
                try
                {
                    if (File.Exists(Path.Combine(c, "qemu", "qemu-system-x86_64.exe")))
                        return Path.GetFullPath(c);
                }
                catch {  }
            }
            return null;
        }

        static string? ResolveSevenZip(string binRoot, string? explicitPath)
        {
            if (!string.IsNullOrWhiteSpace(explicitPath) && File.Exists(explicitPath)) return explicitPath;

            var probes = new List<string>();
            var dir = new DirectoryInfo(binRoot);
            while (dir != null) { probes.Add(Path.Combine(dir.FullName, "7z.exe")); dir = dir.Parent; }
            probes.Add(Path.Combine(AppContext.BaseDirectory, "7z.exe"));

            probes.Add(@"C:\Program Files\7-Zip\7z.exe");
            probes.Add(@"C:\Program Files (x86)\7-Zip\7z.exe");

            foreach (var p in probes) { try { if (File.Exists(p)) return p; } catch { } }

            var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
            foreach (var seg in pathEnv.Split(';'))
            {
                try { var p = Path.Combine(seg.Trim(), "7z.exe"); if (File.Exists(p)) return p; } catch { }
            }
            return null;
        }

        static void WriteStatus(string? path, string stage, string msg)
        {
            if (string.IsNullOrEmpty(path)) return;
            try
            {
                static string J(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"");
                File.WriteAllText(path!, $"{{\"stage\":\"{J(stage)}\",\"msg\":\"{J(msg)}\"}}");
            }
            catch { }
        }

        static void Cleanup(string qcow2, string iso)
        {
            try { if (File.Exists(qcow2)) File.Delete(qcow2); } catch (Exception ex) { Console.WriteLine("  qcow2: " + ex.Message); }
            try { if (File.Exists(iso))   File.Delete(iso);   } catch (Exception ex) { Console.WriteLine("  iso: " + ex.Message); }
        }

        static void Fail(string msg, bool interactive)
        {
            Console.WriteLine("BŁĄD: " + msg);
            if (interactive) { Console.WriteLine("\nNaciśnij dowolny klawisz…"); try { Console.ReadKey(); } catch { } }
        }

        [DllImport("user32.dll")]
        static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct SHSTOCKICONINFO
        {
            public uint cbSize; public IntPtr hIcon; public int iSysImageIndex; public int iIcon;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szPath;
        }
        [DllImport("shell32.dll", SetLastError = true)]
        static extern int SHGetStockIconInfo(uint siid, uint uFlags, ref SHSTOCKICONINFO psii);
        const uint WM_SETICON = 0x0080; const int ICON_BIG = 1; const uint SIID_SHIELD = 77; const uint SHGSI_ICON = 0x100;

        static void ApplyShieldIcon(Process p)
        {
            try
            {
                var sii = new SHSTOCKICONINFO { cbSize = (uint)Marshal.SizeOf(typeof(SHSTOCKICONINFO)) };
                SHGetStockIconInfo(SIID_SHIELD, SHGSI_ICON, ref sii);
                if (p.MainWindowHandle != IntPtr.Zero && sii.hIcon != IntPtr.Zero)
                    SendMessage(p.MainWindowHandle, WM_SETICON, (IntPtr)ICON_BIG, sii.hIcon);
            }
            catch {  }
        }
    }

    internal sealed class SandboxOptions
    {
        public string? ExePath;
        public bool Network = true;
        public int MemoryGb = 2;
        public bool NatRestrict = true;
        public bool Fullscreen = false;
        public string Cpu = "qemu64";
        public int Cores = 2;
        public int Threads = 2;
        public bool HyperThreading = true;
        public string Accel = "auto";
        public string? StatusPath;
        public string? BinDir;
        public string? SevenZip;
        public bool Interactive;

        public static SandboxOptions Parse(string[] args)
        {
            var o = new SandboxOptions();
            string Val(int i) => (i + 1 < args.Length) ? args[i + 1] : "";
            bool OnOff(string v) => !v.Equals("off", StringComparison.OrdinalIgnoreCase)
                                    && !v.Equals("false", StringComparison.OrdinalIgnoreCase)
                                    && !v.Equals("0", StringComparison.OrdinalIgnoreCase);

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i].ToLowerInvariant())
                {
                    case "--exe": o.ExePath = Val(i++); break;
                    case "--net": o.Network = OnOff(Val(i++)); break;
                    case "--mem": if (int.TryParse(Val(i++), out var m)) o.MemoryGb = Math.Clamp(m, 2, 16); break;
                    case "--nat": o.NatRestrict = OnOff(Val(i++)); break;
                    case "--fullscreen": o.Fullscreen = true; break;
                    case "--cpu": o.Cpu = SanitizeCpu(Val(i++)); break;
                    case "--cores": if (int.TryParse(Val(i++), out var c)) o.Cores = Math.Clamp(c, 1, 16); break;
                    case "--threads": if (int.TryParse(Val(i++), out var t)) o.Threads = Math.Clamp(t, 1, 4); break;
                    case "--ht": o.HyperThreading = OnOff(Val(i++)); break;
                    case "--accel":
                        {
                            var a = Val(i++).ToLowerInvariant();
                            o.Accel = (a == "whpx" || a == "tcg") ? a : "auto";
                            break;
                        }
                    case "--status": o.StatusPath = Val(i++); break;
                    case "--bin": o.BinDir = Val(i++); break;
                    case "--sevenzip": o.SevenZip = Val(i++); break;
                }
            }
            o.Interactive = string.IsNullOrWhiteSpace(o.ExePath);
            return o;
        }

        static string SanitizeCpu(string v)
        {
            v = (v ?? "").Trim();
            return v.All(ch => char.IsLetterOrDigit(ch) || ch is '-' or '_' or ',') && v.Length > 0
                ? v : "host";
        }
    }

    internal sealed class HelpOverlay
    {
        private Form? _form;
        private Thread? _thread;

        [DllImport("user32.dll")] private static extern bool GetWindowRect(IntPtr hWnd, out RECT r);
        [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr hWnd);
        [StructLayout(LayoutKind.Sequential)] private struct RECT { public int Left, Top, Right, Bottom; }

        private const string Shortcuts =
            "Skróty zarządzania piaskownicą:\n\n" +
            "•  Ctrl + Alt + F   — tryb pełnego ekranu (włącz/wyłącz)\n" +
            "•  Ctrl + Alt + G   — przechwyć / zwolnij mysz i klawiaturę\n" +
            "•  Ctrl + Alt + 1   — ekran maszyny (system gościa)\n" +
            "•  Ctrl + Alt + 2   — konsola monitora maszyny\n" +
            "•  Ctrl + Alt + +/− — powiększ / pomniejsz okno\n\n" +
            "Aby zakończyć sesję — zamknij okno maszyny.\n" +
            "Dysk i pliki sesji są automatycznie czyszczone po zamknięciu.";

        public static HelpOverlay Launch(Process qemu)
        {
            var ov = new HelpOverlay();
            ov._thread = new Thread(() => ov.Run(qemu)) { IsBackground = true };
            ov._thread.SetApartmentState(ApartmentState.STA);
            ov._thread.Start();
            return ov;
        }

        private void Run(Process qemu)
        {
            try
            {
                Application.EnableVisualStyles();

                var badge = new Label
                {
                    Text = "?",
                    Dock = DockStyle.Bottom,
                    Height = 38,
                    TextAlign = ContentAlignment.MiddleCenter,
                    Font = new Font("Segoe UI", 14f, FontStyle.Bold),
                    BackColor = Color.FromArgb(0x1E, 0x7A, 0x4C),
                    ForeColor = Color.White,
                    Cursor = Cursors.Help,
                };

                var panel = new Label
                {
                    Text = Shortcuts,
                    Dock = DockStyle.Fill,
                    Padding = new Padding(12),
                    Font = new Font("Segoe UI", 9f),
                    BackColor = Color.FromArgb(0x16, 0x1B, 0x22),
                    ForeColor = Color.FromArgb(0xE9, 0xEC, 0xF0),
                    Visible = false,
                };

                _form = new Form
                {
                    FormBorderStyle = FormBorderStyle.None,
                    ShowInTaskbar = false,
                    TopMost = true,
                    StartPosition = FormStartPosition.Manual,
                    Size = new Size(44, 44),
                    BackColor = Color.FromArgb(0x16, 0x1B, 0x22),
                };
                _form.Controls.Add(panel);
                _form.Controls.Add(badge);

                const int collapsedW = 44, collapsedH = 44, expandedW = 380, expandedH = 250;

                void Expand()
                {
                    panel.Visible = true;
                    _form.Size = new Size(expandedW, expandedH);
                    Reposition(qemu, expandedW, expandedH);
                }
                void Collapse()
                {
                    panel.Visible = false;
                    _form.Size = new Size(collapsedW, collapsedH);
                    Reposition(qemu, collapsedW, collapsedH);
                }

                badge.MouseEnter += (_, _) => Expand();
                badge.Click      += (_, _) => { if (panel.Visible) Collapse(); else Expand(); };
                _form.MouseLeave += (_, _) =>
                {
                    var pt = _form.PointToClient(Cursor.Position);
                    if (!_form.ClientRectangle.Contains(pt)) Collapse();
                };
                panel.MouseLeave += (_, _) =>
                {
                    var pt = _form.PointToClient(Cursor.Position);
                    if (!_form.ClientRectangle.Contains(pt)) Collapse();
                };

                var timer = new System.Windows.Forms.Timer { Interval = 500 };
                timer.Tick += (_, _) =>
                {
                    try
                    {
                        if (qemu.HasExited) { timer.Stop(); Application.ExitThread(); return; }
                    }
                    catch { }
                    if (!panel.Visible) Reposition(qemu, collapsedW, collapsedH);
                };
                timer.Start();

                _form.Load += (_, _) => Collapse();
                Application.Run(_form);
            }
            catch {  }
        }

        private void Reposition(Process qemu, int w, int h)
        {
            if (_form == null) return;
            try
            {
                IntPtr hwnd = qemu.MainWindowHandle;
                if (hwnd != IntPtr.Zero && IsWindowVisible(hwnd) && GetWindowRect(hwnd, out var r))
                {
                    int x = r.Left + 8;
                    int y = r.Bottom + 6;
                    var wa = Screen.FromHandle(hwnd).WorkingArea;
                    if (y + h > wa.Bottom) y = r.Bottom - h - 6;
                    if (x + w > wa.Right) x = wa.Right - w - 6;
                    _form.Location = new Point(Math.Max(wa.Left, x), Math.Max(wa.Top, y));
                }
            }
            catch { }
        }

        public void Close()
        {
            try { _form?.BeginInvoke(() => { try { Application.ExitThread(); _form?.Close(); } catch { } }); }
            catch { }
        }
    }
}
