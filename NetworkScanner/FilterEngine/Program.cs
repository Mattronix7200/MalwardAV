using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;
using System.Text.Json;

namespace DNSFilterApp
{
    public class AppConfig
    {
        public string UpstreamDns { get; set; } = "185.228.168.168";
        public bool OnlyMemory { get; set; } = false;
        public List<string> Exclusions { get; set; } = new List<string>();
    }

    class Program
    {
        private const int DnsPort = 53;
        private const string DatabaseFile = "database.vdeb";
        private static string _tempFilePath;

        private static AppConfig _config = new AppConfig();
        private static HashSet<string> _memoryBlacklist = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private static List<long> _domainOffsets = new List<long>();
        private static FileStream _dbStream;
        private static BinaryReader _dbReader;

        private static readonly Dictionary<string, string> DnsProviders = new Dictionary<string, string>
        {
            { "1", "1.1.1.1" },
            { "2", "8.8.8.8" },
            { "3", "9.9.9.9" },
            { "4", "8.26.56.26" },
            { "5", "185.228.168.168" },
            { "6", "76.76.19.19" },
            { "7", "94.140.14.14" },
            { "8", "45.90.28.141" },
            { "9", "103.86.96.100" },
            { "10", "95.85.95.85" },
            { "11", "208.67.222.222" },
            { "12", "86.54.11.1" },
            { "13", "76.76.2.1" },
        };

        static async Task Main(string[] args)
        {
            Console.WriteLine("=== Smart DNS Filter (VDEB) ===");

            LoadConfig();
            ParseArguments(args);

            AppDomain.CurrentDomain.ProcessExit += (s, e) => Cleanup();
            Console.CancelKeyPress += (s, e) => Cleanup();

            if (!InitializeDatabase())
            {
                Console.WriteLine("Naciśnij dowolny klawisz, aby wyjść...");
                Console.ReadKey();
                return;
            }

            try
            {
                using UdpClient udpServer = new UdpClient(new IPEndPoint(IPAddress.Any, DnsPort));
                Console.WriteLine($"[INFO] Serwer DNS aktywny na porcie {DnsPort}");
                Console.WriteLine($"[INFO] Upstream: {_config.UpstreamDns}");
                Console.WriteLine($"[INFO] Tryb: {(_config.OnlyMemory ? "RAM" : "Dysk")}");

                while (true)
                {
                    try
                    {
                        var request = await udpServer.ReceiveAsync();
                        _ = Task.Run(() => HandleDnsQuery(udpServer, request));
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[BŁĄD ODBIORU] {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[BŁĄD KRYTYCZNY SERWERA] {ex.Message}");
                Cleanup();
            }
        }

        private static void LoadConfig()
        {
            if (File.Exists("config.json"))
            {
                try
                {
                    string json = File.ReadAllText("config.json");
                    _config = JsonSerializer.Deserialize<AppConfig>(json) ?? new AppConfig();
                }
                catch
                {
                    _config = new AppConfig();
                }
            }
            else
            {
                Console.WriteLine("[INFO] Tworzenie domyślnego pliku konfiguracyjnego...");
                SaveConfig();
            }
        }

        private static void SaveConfig()
        {
            try
            {
                string json = JsonSerializer.Serialize(_config, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText("config.json", json);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[BŁĄD ZAPISU KONFIG] {ex.Message}");
            }
        }

        private static void ParseArguments(string[] args)
        {
            bool modified = false;
            foreach (var arg in args)
            {
                if (arg.Equals("-onlymemory", StringComparison.OrdinalIgnoreCase))
                {
                    _config.OnlyMemory = true;
                    modified = true;
                }

                if (arg.StartsWith("-dns:", StringComparison.OrdinalIgnoreCase))
                {
                    string val = arg.Substring(5);
                    if (DnsProviders.ContainsKey(val)) _config.UpstreamDns = DnsProviders[val];
                    else _config.UpstreamDns = val;
                    modified = true;
                }

                if (arg.StartsWith("-exclusions:", StringComparison.OrdinalIgnoreCase))
                {
                    string sites = arg.Substring(12).Trim('{', '}');
                    var newExclusions = sites.Split(',').Select(s => s.Trim().ToLower()).ToList();
                    _config.Exclusions.AddRange(newExclusions.Where(x => !_config.Exclusions.Contains(x)));
                    modified = true;
                }
            }
            if (modified) SaveConfig();
        }

        private static bool InitializeDatabase()
        {
            if (!File.Exists(DatabaseFile))
            {
                Console.WriteLine($"[BŁĄD] Brak pliku {DatabaseFile}");
                return false;
            }

            try
            {
                Console.WriteLine("[Baza] Ładowanie...");
                using (FileStream fs = File.OpenRead(DatabaseFile))
                using (GZipStream gz = new GZipStream(fs, CompressionMode.Decompress))
                {
                    if (_config.OnlyMemory)
                    {
                        using BinaryReader br = new BinaryReader(gz);
                        br.ReadBytes(4);
                        br.ReadInt32();
                        List<byte> buffer = new List<byte>();
                        while (true)
                        {
                            try
                            {
                                byte b = br.ReadByte();
                                if (b == 0)
                                {
                                    if (buffer.Count > 0)
                                        _memoryBlacklist.Add(Encoding.UTF8.GetString(buffer.ToArray()));
                                    buffer.Clear();
                                }
                                else buffer.Add(b);
                            }
                            catch (EndOfStreamException) { break; }
                        }
                    }
                    else
                    {
                        _tempFilePath = Path.Combine(Path.GetTempPath(), $"dns_filter_{Guid.NewGuid()}.vdeb.tmp");
                        using (FileStream ts = File.Create(_tempFilePath))
                        {
                            gz.CopyTo(ts);
                        }
                        _dbStream = new FileStream(_tempFilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                        _dbReader = new BinaryReader(_dbStream);
                        _dbStream.Seek(8, SeekOrigin.Begin);

                        while (_dbStream.Position < _dbStream.Length)
                        {
                            _domainOffsets.Add(_dbStream.Position);
                            while (_dbStream.Position < _dbStream.Length && _dbReader.ReadByte() != 0) ;
                        }
                    }
                }
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Baza] Błąd inicjalizacji: {ex.Message}");
                return false;
            }
        }

        private static async Task HandleDnsQuery(UdpClient server, UdpReceiveResult request)
        {
            try
            {
                string domain = ParseDomainName(request.Buffer);
                if (string.IsNullOrEmpty(domain)) return;

                if (_config.Exclusions.Any(e => domain.EndsWith(e, StringComparison.OrdinalIgnoreCase)))
                {
                    await ForwardAndSend(server, request);
                    return;
                }

                bool isBlocked = _config.OnlyMemory ? _memoryBlacklist.Contains(domain) : SearchInFile(domain.ToLower());

                if (isBlocked)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [BLOKADA] {domain}");
                    Console.ResetColor();
                    byte[] response = CreateBlockedResponse(request.Buffer);
                    if (response != null) await server.SendAsync(response, response.Length, request.RemoteEndPoint);
                }
                else
                {
                    await ForwardAndSend(server, request);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[BŁĄD ZAPYTANIA] {ex.Message}");
            }
        }

        private static async Task ForwardAndSend(UdpClient server, UdpReceiveResult request)
        {
            try
            {
                byte[] response = await ForwardQuery(request.Buffer);
                if (response != null) await server.SendAsync(response, response.Length, request.RemoteEndPoint);
            }
            catch { }
        }

        private static bool SearchInFile(string target)
        {
            if (_dbStream == null) return false;
            int left = 0, right = _domainOffsets.Count - 1;
            while (left <= right)
            {
                int mid = left + (right - left) / 2;
                string current;
                lock (_dbStream)
                {
                    _dbStream.Seek(_domainOffsets[mid], SeekOrigin.Begin);
                    current = ReadNullTerminatedString();
                }
                int cmp = string.Compare(current, target, StringComparison.OrdinalIgnoreCase);
                if (cmp == 0) return true;
                if (cmp < 0) left = mid + 1; else right = mid - 1;
            }
            return false;
        }

        private static string ReadNullTerminatedString()
        {
            List<byte> bytes = new List<byte>();
            while (_dbStream.Position < _dbStream.Length)
            {
                byte b = _dbReader.ReadByte();
                if (b == 0) break;
                bytes.Add(b);
            }
            return Encoding.UTF8.GetString(bytes.ToArray());
        }

        private static string ParseDomainName(byte[] buffer)
        {
            try
            {
                if (buffer.Length < 12) return null;
                List<string> parts = new List<string>();
                int pos = 12;
                while (pos < buffer.Length && buffer[pos] != 0)
                {
                    int len = buffer[pos++];
                    if ((len & 0xC0) == 0xC0) break;
                    if (pos + len > buffer.Length) break;
                    parts.Add(Encoding.UTF8.GetString(buffer, pos, len));
                    pos += len;
                }
                return string.Join(".", parts);
            }
            catch { return null; }
        }

        private static byte[] CreateBlockedResponse(byte[] request)
        {
            try
            {
                byte[] response = new byte[request.Length + 16];
                Array.Copy(request, response, request.Length);
                response[2] = 0x81; response[3] = 0x80; response[7] = 0x01;
                int pos = request.Length;
                response[pos++] = 0xc0; response[pos++] = 0x0c;
                response[pos++] = 0x00; response[pos++] = 0x01;
                response[pos++] = 0x00; response[pos++] = 0x01;
                response[pos++] = 0x00; response[pos++] = 0x00;
                response[pos++] = 0x00; response[pos++] = 0x05;
                response[pos++] = 0x00; response[pos++] = 0x04;
                response[pos++] = 0x00; response[pos++] = 0x00;
                response[pos++] = 0x00; response[pos++] = 0x00;
                return response;
            }
            catch { return null; }
        }

        private static async Task<byte[]> ForwardQuery(byte[] query)
        {
            try
            {
                using UdpClient client = new UdpClient();
                client.Client.ReceiveTimeout = 2000;
                await client.SendAsync(query, query.Length, _config.UpstreamDns, 53);
                var receiveTask = client.ReceiveAsync();
                if (await Task.WhenAny(receiveTask, Task.Delay(2000)) == receiveTask)
                {
                    return receiveTask.Result.Buffer;
                }
                return null;
            }
            catch { return null; }
        }

        private static void Cleanup()
        {
            try
            {
                _dbReader?.Dispose();
                _dbStream?.Dispose();
                if (!string.IsNullOrEmpty(_tempFilePath) && File.Exists(_tempFilePath))
                {
                    for (int i = 0; i < 3; i++)
                    {
                        try { File.Delete(_tempFilePath); break; }
                        catch { Thread.Sleep(100); }
                    }
                }
            }
            catch { }
        }
    }
}
