namespace Malward.ResidentShield.Hips;

public static class HipsTrust
{
    public static volatile bool TrustSignedInUserArea;

    public static bool IsTrustedProgram(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        try
        {
            if (!File.Exists(path)) return false;
            if (Malward.Engine.Util.SystemFileCheck.HasValidTrustedSignature(path)) return true;
            return Malward.Engine.Util.SystemFileCheck.IsOwnedByTrustedInstaller(path);
        }
        catch { return false; }
    }

    public static bool InUserWritableArea(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var p = path.Replace('/', '\\');
        string[] marks = { @"\users\", @"\appdata\", @"\temp\", @"\programdata\", @"\public\", @"\downloads\" };
        return marks.Any(m => p.Contains(m, StringComparison.OrdinalIgnoreCase));
    }

    public static string? SuspectReason(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return "nie odnaleziono programu wskazanego przez wpis";
        bool trusted = IsTrustedProgram(path);
        bool userLand = InUserWritableArea(path);
        if (trusted && !userLand) return null;

        if (trusted && TrustSignedInUserArea) return null;
        if (!trusted && userLand) return $"brak zaufanego podpisu, program w katalogu użytkownika: {path}";
        return userLand ? $"program w katalogu użytkownika: {path}" : $"brak zaufanego podpisu: {path}";
    }
}
