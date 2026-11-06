using System.Text.Json.Nodes;

namespace Malward.AppGUI;

public static class FirstRunProfile
{
    public static void HoldShieldsForConsent(JsonObject bundle)
    {
        if (bundle["resident"] is JsonObject rs)
        {
            rs["resident_shield_enabled"] = false;
            rs["network_shield_enabled"] = false;
        }
        if (bundle["network"] is JsonObject nw) nw["enabled"] = false;
    }

    public static bool AnyShieldOn(JsonObject bundle)
        => (bundle["resident"]?["resident_shield_enabled"]?.GetValue<bool>() ?? true)
        || (bundle["resident"]?["network_shield_enabled"]?.GetValue<bool>() ?? true)
        || (bundle["network"]?["enabled"]?.GetValue<bool>() ?? true);
}
