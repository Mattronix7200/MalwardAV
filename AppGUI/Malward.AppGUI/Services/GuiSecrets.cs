using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace Malward.AppGUI.Services;

public static class GuiSecrets
{
    private const int RetryMs = 5000;

    private static string _psk = "";
    private static long _lastTry;
    private static readonly object _lock = new();

    public static string AuthPsk
    {
        get
        {
            if (_psk.Length > 0) return _psk;
            lock (_lock)
            {
                if (_psk.Length > 0) return _psk;
                long now = Environment.TickCount64;
                if (_lastTry != 0 && now - _lastTry < RetryMs) return "";
                _lastTry = now;
                _psk = Resolve();
                return _psk;
            }
        }
    }

    public static bool HasPsk => AuthPsk.Length > 0;

    public static string LastDiagnostic { get; private set; } = "jeszcze nie probowano";

    public static string ConfigPath => CandidatePaths()[0];

    private static string[] CandidatePaths() =>
    [
        Path.Combine(AppContext.BaseDirectory, Malward.Engine.Cloud.ConfigKeyFile.FileName),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                     "Malward", "data", Malward.Engine.Cloud.ConfigKeyFile.FileName),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                     "Malward", "data", "client-auth.json"),
        Path.Combine(AppContext.BaseDirectory, "client-auth.json"),
    ];

    private static string? ReadCandidate(string path)
    {
        var bytes = File.ReadAllBytes(path);
        if (Path.GetFileName(path).Equals(Malward.Engine.Cloud.ConfigKeyFile.FileName,
                                          StringComparison.OrdinalIgnoreCase))
            return Malward.Engine.Cloud.ConfigKeyFile.Unprotect(bytes);
        return System.Text.Encoding.UTF8.GetString(bytes).TrimStart('﻿');
    }

    private static string Resolve()
    {
        var notes = new List<string>();

        try
        {
            var env = Environment.GetEnvironmentVariable("MALWARD_AUTH_PSK");
            if (!string.IsNullOrWhiteSpace(env))
            {
                LastDiagnostic = "ze zmiennej MALWARD_AUTH_PSK";
                return env.Trim();
            }
            notes.Add("MALWARD_AUTH_PSK nieustawiona");
        }
        catch (Exception ex) { notes.Add($"MALWARD_AUTH_PSK: {ex.GetType().Name}"); }

        foreach (var path in CandidatePaths())
        {
            try
            {
                if (!File.Exists(path)) { notes.Add($"{path}: brak pliku"); continue; }
                var text = ReadCandidate(path);
                if (text == null) { notes.Add($"{path}: nie da sie odszyfrowac"); continue; }
                using var doc = JsonDocument.Parse(text);
                if (!doc.RootElement.TryGetProperty("auth_psk", out var el))
                { notes.Add($"{path}: brak pola auth_psk"); continue; }
                var v = el.GetString();
                if (string.IsNullOrWhiteSpace(v))
                { notes.Add($"{path}: auth_psk puste"); continue; }
                LastDiagnostic = $"z pliku {path}";
                return v.Trim();
            }
            catch (Exception ex) { notes.Add($"{path}: {ex.GetType().Name}: {ex.Message}"); }
        }

        LastDiagnostic = string.Join(" | ", notes);
        return string.Empty;
    }
}
