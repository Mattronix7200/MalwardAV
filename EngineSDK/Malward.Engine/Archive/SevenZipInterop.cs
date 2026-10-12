using System.Runtime.InteropServices;

namespace Malward.Engine.Archive;

[ComImport, Guid("23170F69-40C1-278A-0000-000600100000"),
 InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IArchiveOpenCallback
{
    [PreserveSig] int SetTotal(IntPtr files, IntPtr bytes);
    [PreserveSig] int SetCompleted(IntPtr files, IntPtr bytes);
}

[ComImport, Guid("23170F69-40C1-278A-0000-000500100000"),
 InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface ICryptoGetTextPassword
{
    [PreserveSig] int CryptoGetTextPassword([MarshalAs(UnmanagedType.BStr)] out string password);
}

[ComImport, Guid("23170F69-40C1-278A-0000-000300010000"),
 InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface ISequentialInStream
{
    [PreserveSig] int Read(IntPtr data, uint size, IntPtr processedSize);
}

[ComImport, Guid("23170F69-40C1-278A-0000-000300030000"),
 InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IInStream
{
    [PreserveSig] int Read(IntPtr data, uint size, IntPtr processedSize);
    [PreserveSig] int Seek(long offset, uint seekOrigin, IntPtr newPosition);
}

[ComImport, Guid("23170F69-40C1-278A-0000-000300020000"),
 InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface ISequentialOutStream
{
    [PreserveSig] int Write(IntPtr data, uint size, IntPtr processedSize);
}

[ComImport, Guid("23170F69-40C1-278A-0000-000600200000"),
 InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IArchiveExtractCallback
{
    [PreserveSig] int SetTotal(ulong total);
    [PreserveSig] int SetCompleted([In] ref ulong completeValue);
    [PreserveSig] int GetStream(uint index,
        [MarshalAs(UnmanagedType.Interface)] out ISequentialOutStream? outStream, uint askExtractMode);
    [PreserveSig] int PrepareOperation(uint askExtractMode);
    [PreserveSig] int SetOperationResult(uint resultEOperationResult);
}

[ComImport, Guid("23170F69-40C1-278A-0000-000600600000"),
 InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IInArchive
{
    [PreserveSig] int Open(IInStream stream, [In] ref ulong maxCheckStartPosition,
                           IArchiveOpenCallback openCallback);
    [PreserveSig] int Close();
    [PreserveSig] int GetNumberOfItems(out uint numItems);

    [PreserveSig] int GetProperty(uint index, ItemPropId propId, IntPtr value);
    [PreserveSig] int Extract([MarshalAs(UnmanagedType.LPArray)] uint[]? indices, uint numItems,
                              int testMode, IArchiveExtractCallback extractCallback);
    [PreserveSig] int GetArchiveProperty(uint propId, IntPtr value);
    [PreserveSig] int GetNumberOfProperties(out uint numProps);
    [PreserveSig] int GetPropertyInfo(uint index,
        [MarshalAs(UnmanagedType.BStr)] out string name, out ItemPropId propId, out ushort varType);
    [PreserveSig] int GetNumberOfArchiveProperties(out uint numProps);
    [PreserveSig] int GetArchivePropertyInfo(uint index,
        [MarshalAs(UnmanagedType.BStr)] out string name, out ItemPropId propId, out ushort varType);
}

internal enum ItemPropId : uint
{
    Path = 3,
    Name = 4,
    IsFolder = 6,
    Size = 7,
    Attributes = 9,
    Encrypted = 15,
}

internal sealed class PropVariantBuffer : IDisposable
{
    private const int Size = 24;
    private const ushort VT_EMPTY = 0, VT_BOOL = 11, VT_BSTR = 8,
                         VT_UI4 = 19, VT_UI8 = 21, VT_I4 = 3, VT_I8 = 20, VT_FILETIME = 64;
    private const int ValueOffset = 8;

    public IntPtr Ptr { get; }

    public PropVariantBuffer()
    {
        Ptr = Marshal.AllocCoTaskMem(Size);
        Reset();
    }

    public void Reset()
    {
        for (int i = 0; i < Size; i += 8) Marshal.WriteInt64(Ptr, i, 0);
    }

    private ushort Vt => (ushort)Marshal.ReadInt16(Ptr, 0);

    public string? AsString()
    {
        if (Vt != VT_BSTR) return null;
        var bstr = Marshal.ReadIntPtr(Ptr, ValueOffset);
        return bstr == IntPtr.Zero ? null : Marshal.PtrToStringBSTR(bstr);
    }

    public bool AsBoolean() => Vt == VT_BOOL && Marshal.ReadInt16(Ptr, ValueOffset) != 0;

    public ulong AsUInt64() => Vt switch
    {
        VT_UI8 or VT_FILETIME or VT_I8 => (ulong)Marshal.ReadInt64(Ptr, ValueOffset),
        VT_UI4 or VT_I4               => (ulong)(uint)Marshal.ReadInt32(Ptr, ValueOffset),
        _                             => 0UL,
    };

    public void ClearValue()
    {
        if (Vt == VT_BSTR)
        {
            var bstr = Marshal.ReadIntPtr(Ptr, ValueOffset);
            if (bstr != IntPtr.Zero) Marshal.FreeBSTR(bstr);
        }
        Reset();
    }

    public void Dispose()
    {
        ClearValue();
        Marshal.FreeCoTaskMem(Ptr);
    }
}
