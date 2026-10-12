using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json.Nodes;
using System.Threading;

namespace Malward.AppGUI.Services;

public sealed class HipsAlertWatcher : IDisposable
{
    public sealed record Alert(string Rule, string RuleName, string Detail, string Where,
                               string Process, string Kind, bool Blocked, JsonObject? Fix);

    private const int PollMs = 1500;
    private const int MaxBurst = 3;
    private static readonly TimeSpan DedupWindow = TimeSpan.FromMinutes(2);

    private readonly string _file;
    private readonly Action<Alert> _show;
    private readonly Func<bool> _enabled;
    private readonly System.Threading.Timer _timer;
    private readonly Dictionary<string, DateTime> _seen = new(StringComparer.OrdinalIgnoreCase);
    private long _offset;
    private int _busy;
    private bool _disposed;

    public HipsAlertWatcher(Action<Alert> show, Func<bool> enabled)
    {
        _show = show;
        _enabled = enabled;
        _file = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Malward", "data", "hips-events.jsonl");

        try { _offset = File.Exists(_file) ? new FileInfo(_file).Length : 0; } catch { _offset = 0; }

        _timer = new System.Threading.Timer(_ => Poll(), null, PollMs, PollMs);
    }

    private void Poll()
    {
        if (_disposed || Interlocked.Exchange(ref _busy, 1) == 1) return;
        try
        {
            if (!File.Exists(_file)) { _offset = 0; return; }

            long len;
            try { len = new FileInfo(_file).Length; } catch { return; }

            if (len < _offset) { _offset = 0; }
            if (len == _offset) return;

            var lines = new List<string>();
            using (var fs = new FileStream(_file, FileMode.Open, FileAccess.Read,
                                           FileShare.ReadWrite | FileShare.Delete))
            {
                fs.Seek(_offset, SeekOrigin.Begin);
                using var sr = new StreamReader(fs, System.Text.Encoding.UTF8);
                string? line;
                while ((line = sr.ReadLine()) != null)
                    if (line.Length > 0) lines.Add(line);
                _offset = fs.Position;
            }

            if (lines.Count == 0 || !Safe(_enabled)) return;

            int shown = 0;
            foreach (var line in lines)
            {
                if (shown >= MaxBurst) break;
                var a = Parse(line);
                if (a == null) continue;
                if (!Fresh(a)) continue;
                shown++;
                try { _show(a); } catch { }
            }
        }
        catch { }
        finally { Interlocked.Exchange(ref _busy, 0); }
    }

    private static Alert? Parse(string line)
    {
        try
        {
            if (JsonNode.Parse(line) is not JsonObject o) return null;

            var action = o["action"]?.GetValue<string>() ?? "";

            bool blocked = string.Equals(action, "block", StringComparison.OrdinalIgnoreCase);
            bool ask     = string.Equals(action, "ask",   StringComparison.OrdinalIgnoreCase);
            if (!blocked && !ask) return null;

            var who = o["process"]?.GetValue<string>() ?? "";
            bool isCategory = who is "rejestr" or "plik" or "WMI";

            return new Alert(
                Rule:     o["rule"]?.GetValue<string>() ?? "",
                RuleName: o["name"]?.GetValue<string>() ?? "Reguła ochrony",
                Detail:   o["detail"]?.GetValue<string>() ?? "",
                Where:    o["path"]?.GetValue<string>() ?? "",
                Process:  isCategory ? "" : who,
                Kind:     isCategory ? who : "",
                Blocked:  blocked,
                Fix:      o["fix"] as JsonObject);
        }
        catch { return null; }
    }

    private bool Fresh(Alert a)
    {
        var key = a.Rule + "|" + a.Where;
        var now = DateTime.UtcNow;
        lock (_seen)
        {
            if (_seen.TryGetValue(key, out var last) && now - last < DedupWindow) return false;
            _seen[key] = now;
            if (_seen.Count > 400)
            {
                foreach (var k in new List<string>(_seen.Keys))
                    if (now - _seen[k] > DedupWindow) _seen.Remove(k);
            }
        }
        return true;
    }

    public void Mute(string rule, string where)
    {
        lock (_seen) { _seen[rule + "|" + where] = DateTime.UtcNow; }
    }

    private static bool Safe(Func<bool> f)
    {
        try { return f(); } catch { return true; }
    }

    public void Dispose()
    {
        _disposed = true;
        try { _timer.Dispose(); } catch { }
    }
}
