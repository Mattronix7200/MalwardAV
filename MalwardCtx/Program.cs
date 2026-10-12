using System.Diagnostics;
using System.Text;

static string ReqPath() => Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
    "Malward", "inbox", "scan-request.txt");

static void Append(IEnumerable<string> paths)
{
    var sb = new StringBuilder();
    foreach (var p in paths)
    {
        var t = (p ?? "").Trim().Trim('"');
        if (t.Length > 0) sb.Append(t).Append('\n');
    }
    if (sb.Length == 0) return;
    var bytes = new UTF8Encoding(false).GetBytes(sb.ToString());
    var path = ReqPath();
    try { Directory.CreateDirectory(Path.GetDirectoryName(path)!); } catch { }

    for (int i = 0; i < 40; i++)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
            fs.Write(bytes, 0, bytes.Length);
            return;
        }
        catch (IOException) { Thread.Sleep(15); }
        catch (UnauthorizedAccessException) { Thread.Sleep(15); }
    }
}

static void WaitForSelectionToSettle()
{
    const int PROBE_MS = 100;
    const int STABLE_PROBES = 4;
    const int MAX_WAIT_MS = 30_000;
    var path = ReqPath();
    long ostatni = -1;
    int stabilne = 0;
    var start = Environment.TickCount64;

    while (Environment.TickCount64 - start < MAX_WAIT_MS)
    {
        Thread.Sleep(PROBE_MS);
        long teraz;
        try { teraz = new FileInfo(path).Length; }
        catch { teraz = ostatni; }
        if (teraz != ostatni) { ostatni = teraz; stabilne = 0; continue; }
        if (++stabilne >= STABLE_PROBES) return;
    }
}

static bool MalwardRunning()
{
    try
    {
        return Process.GetProcessesByName("malward").Length > 0
            || Process.GetProcessesByName("Malward.AppGUI").Length > 0
            || Process.GetProcessesByName("Malward").Length > 0;
    }
    catch { return false; }
}

static string? ResolveMalward()
{
    var cand = Path.Combine(AppContext.BaseDirectory, "malward.exe");
    return File.Exists(cand) ? cand : null;
}

try
{
    var paths = args.Where(a => !string.IsNullOrWhiteSpace(a)).ToList();
    Append(paths);

    using var mutex = new Mutex(initiallyOwned: true, "Local\\MalwardCtx.Launcher", out bool owner);
    if (!owner) return;
    WaitForSelectionToSettle();

    if (MalwardRunning()) return;
    var exe = ResolveMalward();
    if (exe == null) return;
    Process.Start(new ProcessStartInfo
    {
        FileName        = exe,
        Arguments       = "--scan-request",   
        UseShellExecute = true,
    });
}
catch {  }
