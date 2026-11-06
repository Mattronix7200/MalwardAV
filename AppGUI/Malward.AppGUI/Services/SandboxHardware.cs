using System;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace Malward.AppGUI.Services;

internal static class SandboxHardware
{
    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatusEx
    {
        public uint Length;
        public uint MemoryLoad;
        public ulong TotalPhys;
        public ulong AvailPhys;
        public ulong TotalPageFile;
        public ulong AvailPageFile;
        public ulong TotalVirtual;
        public ulong AvailVirtual;
        public ulong AvailExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatusEx buffer);

    [StructLayout(LayoutKind.Sequential)]
    private struct LogicalProcessorInformation
    {
        public UIntPtr ProcessorMask;
        public int Relationship;
        public ulong Payload0;
        public ulong Payload1;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetLogicalProcessorInformation(IntPtr buffer, ref uint returnLength);

    private const int RelationProcessorCore = 0;

    private static readonly int[] MemorySteps = { 2, 4, 6, 8, 12, 16 };

    public static object Recommend()
    {
        int freeGb = AvailableGb();
        int physical = PhysicalCores();
        int logical = Math.Max(1, Environment.ProcessorCount);
        string vendor = Vendor();
        bool intel = vendor.IndexOf("Intel", StringComparison.OrdinalIgnoreCase) >= 0;
        bool amd = vendor.IndexOf("AMD", StringComparison.OrdinalIgnoreCase) >= 0;
        bool threaded = logical > physical;

        int budget = Math.Clamp(freeGb - 2, 2, 8);
        int mem = MemorySteps[0];
        foreach (var step in MemorySteps)
            if (step <= budget) mem = step;

        int cores = Math.Clamp(physical / 2, 1, 4);

        return new
        {
            mem,
            cores,
            threads = intel && threaded ? 2 : 1,
            ht = intel && threaded,
            cpu = intel ? "Skylake-Client-v2" : amd ? "EPYC-v3" : "qemu64",
            accel = "auto",
            freeGb,
            physical,
            logical,
            vendor,
        };
    }

    private static int AvailableGb()
    {
        try
        {
            var status = new MemoryStatusEx { Length = (uint)Marshal.SizeOf<MemoryStatusEx>() };
            if (GlobalMemoryStatusEx(ref status))
                return (int)(status.AvailPhys / (1024UL * 1024UL * 1024UL));
        }
        catch { }
        return 4;
    }

    private static int PhysicalCores()
    {
        IntPtr buffer = IntPtr.Zero;
        try
        {
            uint size = 0;
            GetLogicalProcessorInformation(IntPtr.Zero, ref size);
            if (size == 0) return Math.Max(1, Environment.ProcessorCount);

            buffer = Marshal.AllocHGlobal((int)size);
            if (!GetLogicalProcessorInformation(buffer, ref size))
                return Math.Max(1, Environment.ProcessorCount);

            int entry = Marshal.SizeOf<LogicalProcessorInformation>();
            int count = 0;
            for (int offset = 0; offset + entry <= size; offset += entry)
            {
                var info = Marshal.PtrToStructure<LogicalProcessorInformation>(buffer + offset);
                if (info.Relationship == RelationProcessorCore) count++;
            }
            return count > 0 ? count : Math.Max(1, Environment.ProcessorCount);
        }
        catch { return Math.Max(1, Environment.ProcessorCount); }
        finally { if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer); }
    }

    private static string Vendor()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"HARDWARE\DESCRIPTION\System\CentralProcessor\0");
            string name = key?.GetValue("ProcessorNameString") as string ?? "";
            string id = key?.GetValue("VendorIdentifier") as string ?? "";
            if (id.IndexOf("Intel", StringComparison.OrdinalIgnoreCase) >= 0
                || name.IndexOf("Intel", StringComparison.OrdinalIgnoreCase) >= 0) return "Intel";
            if (id.IndexOf("AMD", StringComparison.OrdinalIgnoreCase) >= 0
                || name.IndexOf("AMD", StringComparison.OrdinalIgnoreCase) >= 0) return "AMD";
            return id.Length > 0 ? id : "nieznany";
        }
        catch { return "nieznany"; }
    }
}
