using System.ComponentModel;
using System.Net.Sockets;

namespace Malward.NetworkScanner;

internal static class ErrorText
{
    public static string English(Exception ex)
    {
        for (Exception? e = ex; e != null; e = e.InnerException)
        {
            if (e is SocketException se)
                return $"socket error {se.SocketErrorCode} ({(int)se.SocketErrorCode})";
            if (e is Win32Exception we)
                return $"Win32 error {we.NativeErrorCode} (0x{we.NativeErrorCode:X})";
        }

        var root = ex.GetBaseException();
        string name = root.GetType().Name;
        bool ascii = root.Message.All(c => c < 128);
        return ascii ? $"{name}: {root.Message}" : $"{name} (HRESULT 0x{root.HResult:X8})";
    }
}
