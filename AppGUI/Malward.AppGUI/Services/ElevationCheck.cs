using System.Security.Principal;

namespace Malward.AppGUI.Services;

public static class ElevationCheck
{
    public static bool IsAdministrator
    {
        get
        {
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }
    }

    public static string? CurrentUserName
    {
        get
        {
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                return identity.Name;
            }
            catch { return null; }
        }
    }
}
