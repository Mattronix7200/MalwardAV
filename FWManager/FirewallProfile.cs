using System.Globalization;
using System.Runtime.InteropServices;

namespace Malward.FWManager;

public sealed class FirewallProfileState
{
    public int CurrentProfileTypes { get; init; }
    public bool DomainEnabled  { get; init; }
    public bool PrivateEnabled { get; init; }
    public bool PublicEnabled  { get; init; }
}

public static class FirewallProfile
{
    public const int NET_FW_PROFILE2_DOMAIN  = 1;
    public const int NET_FW_PROFILE2_PRIVATE = 2;
    public const int NET_FW_PROFILE2_PUBLIC  = 4;

    public static FirewallProfileState GetState()
    {
        dynamic? policy = null;
        try
        {
            var t = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            policy = Activator.CreateInstance(t!)!;
            int cur = policy.CurrentProfileTypes;
            return new FirewallProfileState
            {
                CurrentProfileTypes = cur,
                DomainEnabled  = policy.FirewallEnabled[NET_FW_PROFILE2_DOMAIN],
                PrivateEnabled = policy.FirewallEnabled[NET_FW_PROFILE2_PRIVATE],
                PublicEnabled  = policy.FirewallEnabled[NET_FW_PROFILE2_PUBLIC],
            };
        }
        catch { return new FirewallProfileState(); }
        finally { if (policy != null) try { Marshal.ReleaseComObject(policy); } catch { } }
    }

    private static void AnnounceOwnChange()
    {
        try
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Malward", "data");
            Directory.CreateDirectory(dir);
            File.WriteAllText(Path.Combine(dir, "fw-intent"),
                              DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture));
        }
        catch { }
    }

    public static (bool ok, string? error) SetProfileEnabled(int profile, bool enabled)
    {
        AnnounceOwnChange();
        dynamic? policy = null;
        try
        {
            var t = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            policy = Activator.CreateInstance(t!)!;
            policy.FirewallEnabled[profile] = enabled;
            return (true, null);
        }
        catch (Exception ex) { return (false, ex.Message); }
        finally { if (policy != null) try { Marshal.ReleaseComObject(policy); } catch { } }
    }

    public static int GetDefaultOutboundAction(int profile)
    {
        dynamic? policy = null;
        try
        {
            var t = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            policy = Activator.CreateInstance(t!)!;
            return (int)policy.DefaultOutboundAction[profile];
        }
        catch { return 1;  }
        finally { if (policy != null) try { Marshal.ReleaseComObject(policy); } catch { } }
    }

    public static (bool ok, string? error) SetDefaultOutboundAction(int profile, int action)
    {
        AnnounceOwnChange();
        dynamic? policy = null;
        try
        {
            var t = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            policy = Activator.CreateInstance(t!)!;
            policy.DefaultOutboundAction[profile] = action;
            return (true, null);
        }
        catch (Exception ex) { return (false, ex.Message); }
        finally { if (policy != null) try { Marshal.ReleaseComObject(policy); } catch { } }
    }

    public static (bool ok, string? error) SetAllProfilesEnabled(bool enabled)
    {
        var errors = new List<string>();
        foreach (var p in new[] { NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC })
        {
            var (ok, err) = SetProfileEnabled(p, enabled);
            if (!ok && !string.IsNullOrEmpty(err)) errors.Add(err);
        }
        return errors.Count == 0 ? (true, null) : (false, string.Join("; ", errors));
    }

    public static (bool ok, string? error) SetMasterBlockMode(bool blockMode)
    {
        int action = blockMode ? 0  : 1 ;
        var errors = new List<string>();
        foreach (var p in new[] { NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC })
        {
            var (ok, err) = SetDefaultOutboundAction(p, action);
            if (!ok && !string.IsNullOrEmpty(err)) errors.Add(err);
        }
        return errors.Count == 0 ? (true, null) : (false, string.Join("; ", errors));
    }
}
