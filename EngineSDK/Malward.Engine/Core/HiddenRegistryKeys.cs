using System.Runtime.InteropServices;

namespace Malward.Engine.Core;

public static class HiddenRegistryKeys
{
    private const int STATUS_SUCCESS = 0;
    private const int STATUS_NO_MORE_ENTRIES = unchecked((int)0x8000001A);
    private const int STATUS_BUFFER_TOO_SMALL = unchecked((int)0xC0000023);
    private const int STATUS_BUFFER_OVERFLOW = unchecked((int)0x80000005);

    private const int KeyBasicInformation = 0;

    [DllImport("ntdll.dll")]
    private static extern int NtEnumerateKey(IntPtr keyHandle, int index, int infoClass,
        byte[]? keyInfo, int length, out int resultLength);

    public readonly record struct Hidden(string ParentPath, string RawName);

    public static List<Hidden> Scan(IEnumerable<(string Label, Microsoft.Win32.RegistryKey Root, string SubPath)> roots,
                                    int maxDepth = 3)
    {
        var found = new List<Hidden>();
        foreach (var (label, root, sub) in roots)
        {
            try
            {
                using var k = string.IsNullOrEmpty(sub) ? root : root.OpenSubKey(sub);
                if (k == null) continue;
                Walk(k, label + (string.IsNullOrEmpty(sub) ? "" : "\\" + sub), found, 0, maxDepth);
            }
            catch { }
        }
        return found;
    }

    private static void Walk(Microsoft.Win32.RegistryKey key, string path,
                             List<Hidden> found, int depth, int maxDepth)
    {
        if (depth > maxDepth) return;

        var natywne = EnumerateNative(key);
        foreach (var n in natywne)
        {
            if (n.IndexOf('\0') < 0) continue;
            found.Add(new Hidden(path, n.Replace("\0", "<NUL>")));
        }

        string[] dzieci;
        try { dzieci = key.GetSubKeyNames(); } catch { return; }
        foreach (var d in dzieci)
        {
            try
            {
                using var sk = key.OpenSubKey(d);
                if (sk != null) Walk(sk, path + "\\" + d, found, depth + 1, maxDepth);
            }
            catch { }
        }
    }

    private static List<string> EnumerateNative(Microsoft.Win32.RegistryKey key)
    {
        var wynik = new List<string>();
        IntPtr h;
        try { h = key.Handle.DangerousGetHandle(); }
        catch { return wynik; }
        if (h == IntPtr.Zero) return wynik;

        var bufor = new byte[1024];
        for (int i = 0; i < 4096; i++)
        {
            int status = NtEnumerateKey(h, i, KeyBasicInformation, bufor, bufor.Length, out int potrzeba);
            if (status == STATUS_BUFFER_TOO_SMALL || status == STATUS_BUFFER_OVERFLOW)
            {
                if (potrzeba <= 0 || potrzeba > 1 << 20) break;
                bufor = new byte[potrzeba];
                status = NtEnumerateKey(h, i, KeyBasicInformation, bufor, bufor.Length, out _);
            }
            if (status == STATUS_NO_MORE_ENTRIES) break;
            if (status != STATUS_SUCCESS) break;

            const int offsetDlugosci = 8 + 4;
            const int offsetNazwy = offsetDlugosci + 4;
            if (bufor.Length < offsetNazwy) break;

            int dlugoscBajtow = BitConverter.ToInt32(bufor, offsetDlugosci);
            if (dlugoscBajtow <= 0 || offsetNazwy + dlugoscBajtow > bufor.Length) continue;

            var nazwa = System.Text.Encoding.Unicode.GetString(bufor, offsetNazwy, dlugoscBajtow);
            wynik.Add(nazwa);
        }
        return wynik;
    }
}
