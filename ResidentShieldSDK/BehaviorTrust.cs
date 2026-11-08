namespace Malward.ResidentShield;

public static class BehaviorTrust
{
    public static volatile bool TrustValidSignature;

    public static void Apply(string? tier, bool settingEnabled)
    {
        string t = (tier ?? "").Trim().ToLowerInvariant();
        TrustValidSignature = settingEnabled && t is "low" or "medium";
    }

    public static bool HasTrustedPublisher(string? imagePath)
    {
        if (string.IsNullOrWhiteSpace(imagePath)) return false;
        try
        {
            if (!File.Exists(imagePath)) return false;
            if (Malward.Engine.Util.SystemFileCheck.HasValidTrustedSignature(imagePath)) return true;
            return Malward.Engine.Util.SystemFileCheck.IsOwnedByTrustedInstaller(imagePath);
        }
        catch { return false; }
    }

    public static string Describe(string? tier)
    {
        string t = (tier ?? "").Trim().ToLowerInvariant();
        if (!TrustValidSignature)
        {
            return t is "high" or "paranoic"
                ? $"profile \"{t}\": a valid signature alone does not grant trust"
                : "turned off in settings: a valid signature alone does not grant trust";
        }
        return $"profile \"{t}\": a valid signature or TrustedInstaller ownership grants trust";
    }
}
