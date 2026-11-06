using System.Security.Principal;

namespace Malward.ConsoleShell;

public static class Elevation
{
    private static bool? _cached;

    public static bool IsAdministrator
    {
        get
        {
            if (_cached.HasValue) return _cached.Value;
            bool ok;
            try
            {
                using var id = WindowsIdentity.GetCurrent();
                ok = new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { ok = false; }
            _cached = ok;
            return ok;
        }
    }

    public static void WarnNotElevated(string what)
    {
        Console.Error.WriteLine();
        Console.Error.WriteLine("[!] Administrator rights are required for " + what + ".");
        Console.Error.WriteLine("    The quarantine store lives under %ProgramData%\\Malward and is not");
        Console.Error.WriteLine("    writable from a standard console. Start the console as administrator");
        Console.Error.WriteLine("    and run the command again.");
        Console.Error.WriteLine();
    }
}
