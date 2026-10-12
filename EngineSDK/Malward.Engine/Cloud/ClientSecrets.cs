using System.Text.Json;

namespace Malward.Engine.Cloud;

public static class ClientSecrets
{
    private const string EnvVar = "MALWARD_AUTH_PSK";

    private static readonly Slot _psk  = new(EnvVar, "auth_psk");
    private static readonly Slot _heur = new("MALWARD_HEUR_PASSWORD", "heur_password");

    public static string AuthPsk => _psk.Value;

    public static bool HasPsk => AuthPsk.Length > 0;

    public static string HeurPassword => _heur.Value;

    public static string ConfigPath => CandidatePaths()[0];

    public static string LastDiagnostic { get; private set; } = "jeszcze nie probowano";

    private static string[] CandidatePaths() =>
    [
        Path.Combine(AppContext.BaseDirectory, ConfigKeyFile.FileName),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                     "Malward", "data", ConfigKeyFile.FileName),

        Path.Combine(AppContext.BaseDirectory, ConfigKeyFile.LegacyFileName),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                     "Malward", "data", ConfigKeyFile.LegacyFileName),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                     "Malward", "data", "client-auth.json"),
        Path.Combine(AppContext.BaseDirectory, "client-auth.json"),
    ];

    private static string? ReadCandidate(string path)
    {
        var bytes = File.ReadAllBytes(path);

        if (ConfigKeyFile.LooksLikeContainer(bytes))
            return ConfigKeyFile.Unprotect(bytes);

        return new StreamReader(new MemoryStream(bytes), detectEncodingFromByteOrderMarks: true).ReadToEnd().TrimStart('﻿');
    }

    private sealed class Slot(string envVar, string jsonField)
    {
        private const int RetryMs = 5000;
        private readonly object _lock = new();
        private string _value = "";
        private long _lastTry;

        public string Value
        {
            get
            {
                if (_value.Length > 0) return _value;
                lock (_lock)
                {
                    if (_value.Length > 0) return _value;
                    long now = Environment.TickCount64;
                    if (_lastTry != 0 && now - _lastTry < RetryMs) return "";
                    _lastTry = now;
                    _value = Read(envVar, jsonField);
                    return _value;
                }
            }
        }
    }

    private static string Read(string envVar, string jsonField)
    {
        var notes = new List<string>();

        try
        {
            var env = Environment.GetEnvironmentVariable(envVar);
            if (!string.IsNullOrWhiteSpace(env))
            {
                LastDiagnostic = $"ze zmiennej {envVar}";
                return env.Trim();
            }
            notes.Add($"{envVar} nieustawiona");
        }
        catch (Exception ex) { notes.Add($"{envVar}: {ex.GetType().Name}"); }

        foreach (var path in CandidatePaths())
        {
            try
            {
                if (!File.Exists(path)) { notes.Add($"{path}: brak pliku"); continue; }
                var text = ReadCandidate(path);
                if (text == null) { notes.Add($"{path}: nie da sie odszyfrowac"); continue; }
                using var doc = JsonDocument.Parse(text);
                if (!doc.RootElement.TryGetProperty(jsonField, out var el))
                { notes.Add($"{path}: brak pola {jsonField}"); continue; }
                var v = el.GetString();
                if (string.IsNullOrWhiteSpace(v))
                { notes.Add($"{path}: {jsonField} puste"); continue; }
                LastDiagnostic = $"z pliku {path}";
                return v.Trim();
            }
            catch (Exception ex) { notes.Add($"{path}: {ex.GetType().Name}: {ex.Message}"); }
        }

        LastDiagnostic = string.Join(" | ", notes);
        return string.Empty;
    }
}
