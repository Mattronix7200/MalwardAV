using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace Malward.BackupEngine;

public static class BootSectorGuard
{
    private const int HeadSectors = 34;
    private const int TailSectors = 33;
    private static readonly byte[] Magic = "MWBOOT01"u8.ToArray();

    private static string StoreDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data", "boot-backup");

    private const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000;
    private const uint FILE_SHARE_READ = 1, FILE_SHARE_WRITE = 2;
    private const uint OPEN_EXISTING = 3;
    private const uint IOCTL_DISK_GET_LENGTH_INFO    = 0x0007405C;
    private const uint IOCTL_DISK_GET_DRIVE_GEOMETRY = 0x00070000;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share,
        IntPtr sec, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(SafeFileHandle h, uint code, IntPtr inBuf, uint inSize,
        byte[] outBuf, uint outSize, out uint returned, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFilePointerEx(SafeFileHandle h, long distance, out long newPtr, uint method);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReadFile(SafeFileHandle h, byte[] buf, uint count, out uint read, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WriteFile(SafeFileHandle h, byte[] buf, uint count, out uint written, IntPtr overlapped);

    private sealed record DriveImage(int SectorSize, long DiskLength, byte[] Head, byte[]? Tail);

    public static object Backup()
    {
        Directory.CreateDirectory(StoreDir);
        var results = new List<object>();
        foreach (var idx in EnumeratePhysicalDrives())
        {
            try
            {
                var img = ReadDrive(idx);
                if (img == null) { results.Add(new { drive = idx, backed_up = false, error = "odczyt nieudany" }); continue; }
                WriteBak(idx, img);
                results.Add(new
                {
                    drive = idx, backed_up = true, sector_size = img.SectorSize,
                    disk_bytes = img.DiskLength, head_sha = Sha(img.Head),
                    tail = img.Tail != null,
                });
            }
            catch (Exception ex) { results.Add(new { drive = idx, backed_up = false, error = ex.Message }); }
        }
        return new { store = StoreDir, drives = results };
    }

    public static object Status()
    {
        var results = new List<object>();
        foreach (var idx in EnumeratePhysicalDrives())
        {
            string bak = BakPath(idx);
            if (!File.Exists(bak)) { results.Add(new { drive = idx, state = "no-backup" }); continue; }
            try
            {
                var stored = ReadBak(bak);
                var cur = ReadDrive(idx);
                if (cur == null) { results.Add(new { drive = idx, state = "read-error" }); continue; }
                bool same = Sha(cur.Head) == Sha(stored.Head);
                results.Add(new
                {
                    drive = idx,
                    state = same ? "clean" : "changed",
                    backup_head_sha = Sha(stored.Head),
                    current_head_sha = Sha(cur.Head),
                });
            }
            catch (Exception ex) { results.Add(new { drive = idx, state = "error", error = ex.Message }); }
        }
        return new { store = StoreDir, drives = results };
    }

    public static object Restore(int? onlyDrive, bool all)
    {
        var results = new List<object>();
        var targets = onlyDrive.HasValue ? new[] { onlyDrive.Value } : EnumeratePhysicalDrives().ToArray();
        foreach (var idx in targets)
        {
            string bak = BakPath(idx);
            if (!File.Exists(bak)) { results.Add(new { drive = idx, restored = false, error = "brak kopii" }); continue; }
            try
            {
                var stored = ReadBak(bak);

                var cur = ReadDrive(idx);
                if (cur == null) { results.Add(new { drive = idx, restored = false, error = "odczyt bieżącego nieudany" }); continue; }
                if (cur.SectorSize != stored.SectorSize || cur.DiskLength != stored.DiskLength)
                {
                    results.Add(new { drive = idx, restored = false, error = "geometria dysku nie zgadza się z kopią (pominięto dla bezpieczeństwa)" });
                    continue;
                }
                bool ok = WriteDrive(idx, stored, all );
                results.Add(new { drive = idx, restored = ok });
            }
            catch (Exception ex) { results.Add(new { drive = idx, restored = false, error = ex.Message }); }
        }
        return new { drives = results };
    }

    private static IEnumerable<int> EnumeratePhysicalDrives()
    {
        for (int i = 0; i < 16; i++)
        {
            SafeFileHandle? h = null;
            try
            {
                h = CreateFileW($@"\\.\PhysicalDrive{i}", GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
                if (!h.IsInvalid) yield return i;
            }
            finally { h?.Dispose(); }
        }
    }

    private static DriveImage? ReadDrive(int idx)
    {
        using var h = CreateFileW($@"\\.\PhysicalDrive{idx}", GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (h.IsInvalid) return null;

        int sector = QuerySectorSize(h);
        long length = QueryLength(h);

        var head = ReadAt(h, 0, HeadSectors * sector);
        if (head == null) return null;

        byte[]? tail = null;
        if (length > (HeadSectors + TailSectors) * (long)sector)
        {
            long tailOffset = (length - TailSectors * (long)sector) / sector * sector;
            tail = ReadAt(h, tailOffset, TailSectors * sector);
        }
        return new DriveImage(sector, length, head, tail);
    }

    private static bool WriteDrive(int idx, DriveImage img, bool includeTail)
    {
        using var h = CreateFileW($@"\\.\PhysicalDrive{idx}", GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (h.IsInvalid) throw new IOException($"open write PhysicalDrive{idx} err={Marshal.GetLastWin32Error()}");

        bool ok = WriteAt(h, 0, img.Head);
        if (includeTail && img.Tail != null)
        {
            long tailOffset = (img.DiskLength - TailSectors * (long)img.SectorSize) / img.SectorSize * img.SectorSize;
            ok &= WriteAt(h, tailOffset, img.Tail);
        }
        return ok;
    }

    private static byte[]? ReadAt(SafeFileHandle h, long offset, int count)
    {
        if (!SetFilePointerEx(h, offset, out _, 0 )) return null;
        var buf = new byte[count];
        if (!ReadFile(h, buf, (uint)count, out uint read, IntPtr.Zero) || read != count) return null;
        return buf;
    }

    private static bool WriteAt(SafeFileHandle h, long offset, byte[] data)
    {
        if (!SetFilePointerEx(h, offset, out _, 0)) return false;
        return WriteFile(h, data, (uint)data.Length, out uint written, IntPtr.Zero) && written == data.Length;
    }

    private static int QuerySectorSize(SafeFileHandle h)
    {
        var outBuf = new byte[24];
        if (DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY, IntPtr.Zero, 0, outBuf, 24, out _, IntPtr.Zero))
        {
            int bps = BitConverter.ToInt32(outBuf, 20);
            if (bps is 512 or 1024 or 2048 or 4096) return bps;
        }
        return 512;
    }

    private static long QueryLength(SafeFileHandle h)
    {
        var outBuf = new byte[8];
        if (DeviceIoControl(h, IOCTL_DISK_GET_LENGTH_INFO, IntPtr.Zero, 0, outBuf, 8, out _, IntPtr.Zero))
            return BitConverter.ToInt64(outBuf, 0);
        return 0;
    }

    private static string BakPath(int idx) => Path.Combine(StoreDir, $"drive{idx}.mbrbak");

    private static void WriteBak(int idx, DriveImage img)
    {
        using var fs = new FileStream(BakPath(idx), FileMode.Create, FileAccess.Write);
        using var bw = new BinaryWriter(fs);
        bw.Write(Magic);
        bw.Write(1);
        bw.Write(img.SectorSize);
        bw.Write(img.DiskLength);
        bw.Write(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        bw.Write(img.Head.Length); bw.Write(img.Head);
        bw.Write(img.Tail?.Length ?? 0);
        if (img.Tail != null) bw.Write(img.Tail);
    }

    private static DriveImage ReadBak(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read);
        using var br = new BinaryReader(fs);
        var magic = br.ReadBytes(Magic.Length);
        if (!magic.AsSpan().SequenceEqual(Magic)) throw new InvalidDataException("zły magic kopii boot");
        br.ReadInt32();
        int sector = br.ReadInt32();
        long length = br.ReadInt64();
        br.ReadInt64();
        int headLen = br.ReadInt32(); var head = br.ReadBytes(headLen);
        int tailLen = br.ReadInt32(); byte[]? tail = tailLen > 0 ? br.ReadBytes(tailLen) : null;
        return new DriveImage(sector, length, head, tail);
    }

    private static string Sha(byte[] data)
        => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
}
