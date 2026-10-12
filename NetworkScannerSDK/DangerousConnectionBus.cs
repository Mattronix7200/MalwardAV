namespace Malward.NetworkScanner;

public sealed record DangerousConnection(
    int    Pid,
    string ProcessName,
    string ImagePath,
    string RemoteIp,
    int    RemotePort,
    string Detection);

public static class DangerousConnectionBus
{
    public static Action<DangerousConnection>? Handler;

    public static bool HasHandler => Handler != null;

    public static void Raise(DangerousConnection connection)
    {
        var handler = Handler;
        if (handler == null) return;
        try { handler(connection); }
        catch (Exception ex) { Log.Warn("ConnMon", $"dangerous-connection handler: {ex.Message}"); }
    }
}
