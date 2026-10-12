using System.Security.Principal;

namespace Malward.Engine.Util;

public static class AdminCheck
{
    public static bool IsAdmin()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            var p = new WindowsPrincipal(id);
            return p.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    public static void RequireAdmin()
    {
        if (IsAdmin()) return;
        Console.Error.WriteLine(
            "[!] Malward.Engine wymaga uprawnień administratora. " +
            "Uruchom jako administrator (np. RunAs).");
        Environment.Exit(5);
    }
}
