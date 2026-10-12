using System.Security.Cryptography;
using System.Text;

namespace Malward.Engine.Util;

public static class PeImpHash
{
    public static string? Compute(string filePath)
    {
        try { return Compute(File.ReadAllBytes(filePath)); }
        catch { return null; }
    }

    public static string? Compute(byte[] data)
    {
        try
        {
            if (data.Length < 0x40 || data[0] != (byte)'M' || data[1] != (byte)'Z') return null;
            int peOff = (int)ReadU32(data, 0x3C);
            if (peOff <= 0 || peOff + 24 > data.Length) return null;
            if (data[peOff] != (byte)'P' || data[peOff + 1] != (byte)'E'
                || data[peOff + 2] != 0 || data[peOff + 3] != 0) return null;

            int coff = peOff + 4;
            int numSections     = ReadU16(data, coff + 2);
            int sizeOptionalHdr = ReadU16(data, coff + 16);
            int optHdr = coff + 20;
            if (optHdr + sizeOptionalHdr > data.Length || numSections <= 0 || numSections > 96) return null;

            int magic = ReadU16(data, optHdr);
            bool pe32Plus = magic == 0x20B;
            if (magic != 0x10B && magic != 0x20B) return null;
            int ddOff  = optHdr + (pe32Plus ? 112 : 96);
            int numRva = (int)ReadU32(data, optHdr + (pe32Plus ? 108 : 92));
            if (numRva < 2) return null;
            uint importRva = ReadU32(data, ddOff + 1 * 8);
            if (importRva == 0) return null;

            int secTable = optHdr + sizeOptionalHdr;
            var sections = new List<(uint va, uint vsize, uint praw, uint rawsize)>(numSections);
            for (int i = 0; i < numSections; i++)
            {
                int s = secTable + i * 40;
                if (s + 40 > data.Length) return null;
                sections.Add((ReadU32(data, s + 12), ReadU32(data, s + 8),
                              ReadU32(data, s + 20), ReadU32(data, s + 16)));
            }

            int? RvaToOff(uint rva)
            {
                foreach (var sec in sections)
                {
                    uint size = Math.Max(sec.vsize, sec.rawsize);
                    if (rva >= sec.va && rva < sec.va + size)
                    {
                        long off = sec.praw + (rva - sec.va);
                        return off >= 0 && off < data.Length ? (int)off : null;
                    }
                }
                return null;
            }

            if (RvaToOff(importRva) is not int descOff) return null;

            var entries = new List<string>();
            int thunkSize = pe32Plus ? 8 : 4;
            ulong ordinalFlag = pe32Plus ? 0x8000000000000000UL : 0x80000000UL;

            for (int guard = 0; guard < 4096; guard++)
            {
                if (descOff + 20 > data.Length) break;
                uint origFirstThunk = ReadU32(data, descOff + 0);
                uint nameRva        = ReadU32(data, descOff + 12);
                uint firstThunk     = ReadU32(data, descOff + 16);
                if (origFirstThunk == 0 && nameRva == 0 && firstThunk == 0) break;

                string dll = ReadDllName(data, RvaToOff(nameRva));
                if (dll.Length > 0)
                {
                    uint thunkRva = origFirstThunk != 0 ? origFirstThunk : firstThunk;
                    if (RvaToOff(thunkRva) is int toff)
                    {
                        for (int k = 0; k < 8192; k++)
                        {
                            int t = toff + k * thunkSize;
                            if (t + thunkSize > data.Length) break;
                            ulong val = pe32Plus ? ReadU64(data, t) : ReadU32(data, t);
                            if (val == 0) break;

                            string func;
                            if ((val & ordinalFlag) != 0)
                                func = "ord" + (val & 0xFFFF).ToString();
                            else
                            {
                                int? hintOff = RvaToOff((uint)(val & 0x7FFFFFFF));
                                func = hintOff is int ho ? ReadAscii(data, ho + 2, 256) : "";
                            }
                            if (func.Length > 0)
                                entries.Add(dll.ToLowerInvariant() + "." + func.ToLowerInvariant());
                        }
                    }
                }
                descOff += 20;
            }

            if (entries.Count == 0) return null;
            var md5 = MD5.HashData(Encoding.ASCII.GetBytes(string.Join(",", entries)));
            return Convert.ToHexString(md5).ToLowerInvariant();
        }
        catch { return null; }
    }

    private static ushort ReadU16(byte[] b, int o) => (ushort)(b[o] | (b[o + 1] << 8));
    private static uint ReadU32(byte[] b, int o)
        => (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24));
    private static ulong ReadU64(byte[] b, int o)
        => ReadU32(b, o) | ((ulong)ReadU32(b, o + 4) << 32);

    private static string ReadDllName(byte[] b, int? off)
    {
        if (off is not int o) return "";
        string name = ReadAscii(b, o, 256);

        int dot = name.LastIndexOf('.');
        if (dot > 0)
        {
            string ext = name[(dot + 1)..].ToLowerInvariant();
            if (ext is "dll" or "ocx" or "sys") name = name[..dot];
        }
        return name;
    }

    private static string ReadAscii(byte[] b, int off, int max)
    {
        if (off < 0 || off >= b.Length) return "";
        var sb = new StringBuilder();
        for (int i = 0; i < max && off + i < b.Length; i++)
        {
            byte c = b[off + i];
            if (c == 0) break;
            if (c < 0x20 || c > 0x7E) return sb.ToString();
            sb.Append((char)c);
        }
        return sb.ToString();
    }
}
