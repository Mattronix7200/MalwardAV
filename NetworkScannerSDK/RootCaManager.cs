using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Malward.NetworkScanner;

public sealed class RootCaManager
{
    private static readonly string CaDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "ca");
    private static readonly string KeyBlobPath = Path.Combine(CaDir, "malward-ca.dpapi");
    private static readonly string PubCertPath = Path.Combine(CaDir, "malward-ca.cer");
    private static readonly string StateFlagPath = Path.Combine(CaDir, "installed.flag");

    private static readonly string DiagPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "logs", "ca-install.log");

    private static void Diag(string line)
    {
        try
        {
            Directory.CreateDirectory(CaDir);
            File.AppendAllText(DiagPath,
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {line}{Environment.NewLine}");
        }
        catch { }
    }

    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("Malward.RootCA.v1");

    private X509Certificate2? _rootWithKey;
    private readonly object _lock = new();

    public bool IsAvailable => _rootWithKey != null;
    public X509Certificate2? RootWithKey { get { lock (_lock) return _rootWithKey; } }

    public void EnsureInstalled()
    {
        lock (_lock)
        {
            try
            {
                Directory.CreateDirectory(CaDir);
                Diag("=== EnsureInstalled START ===");
                if (File.Exists(KeyBlobPath) && File.Exists(PubCertPath))
                {
                    Diag($"Found existing files: {KeyBlobPath}, {PubCertPath}");
                    if (TryLoadExisting()) { Diag("Loaded existing root OK"); return; }

                    if (TryRepairAclAndReload())
                    {
                        Diag("Loaded existing root OK after ACL repair");
                        Log.Info("RootCA", "Restored access to the existing root certificate.");
                        return;
                    }

                    if (_lastLoadWasDenied && !RunningAsOwnerAccount())
                    {
                        Diag("TryLoadExisting denied — the key belongs to another account; NOT regenerating");
                        Log.Warn("RootCA", "The existing root certificate is not readable by this account "
                                         + "(it belongs to SYSTEM). TLS inspection stays off in this process; "
                                         + "the resident service owns the certificate authority.");
                        return;
                    }

                    Diag("TryLoadExisting failed — regenerating");
                    Log.Warn("RootCA", "Failed to load the existing root — generating a new one.");
                }
                else
                {
                    Diag($"No existing files (key={File.Exists(KeyBlobPath)}, cert={File.Exists(PubCertPath)})");
                }
                GenerateAndInstall();
                Diag("=== EnsureInstalled DONE ===");
            }
            catch (Exception ex)
            {
                Diag($"!!! EnsureInstalled THREW: {ex.GetType().Name}: {ex.Message}\n{ex.StackTrace}");
                Log.Error("RootCA", $"EnsureInstalled failed: {ex.Message}");
            }
        }
    }

    private bool TryRepairAclAndReload()
    {
        try
        {
            foreach (var path in new[] { KeyBlobPath, PubCertPath })
            {
                if (!File.Exists(path)) continue;
                try
                {
                    var fi = new FileInfo(path);
                    fi.Attributes = FileAttributes.Normal;

                    var ac = fi.GetAccessControl();
                    ac.SetOwner(new System.Security.Principal.SecurityIdentifier(
                        System.Security.Principal.WellKnownSidType.LocalSystemSid, null));
                    foreach (var sid in new[]
                    {
                        System.Security.Principal.WellKnownSidType.LocalSystemSid,
                        System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid,
                    })
                    {
                        ac.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                            new System.Security.Principal.SecurityIdentifier(sid, null),
                            System.Security.AccessControl.FileSystemRights.FullControl,
                            System.Security.AccessControl.AccessControlType.Allow));
                    }
                    fi.SetAccessControl(ac);
                    Diag($"TryRepairAclAndReload: ACL repaired for {Path.GetFileName(path)}");
                }
                catch (Exception ex)
                {
                    Diag($"TryRepairAclAndReload: {Path.GetFileName(path)} — {ex.GetType().Name}: {ex.Message}");
                }
            }
            return TryLoadExisting();
        }
        catch (Exception ex)
        {
            Diag($"TryRepairAclAndReload THREW: {ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }

    private bool _lastLoadWasDenied;

    private static bool RunningAsOwnerAccount()
    {
        try
        {
            using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            if (id.IsSystem) return true;
            return new System.Security.Principal.WindowsPrincipal(id)
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    private bool TryLoadExisting()
    {
        byte[]? keyDer = null;
        _lastLoadWasDenied = false;
        try
        {
            Diag("TryLoadExisting: ReadAllBytes(KeyBlobPath)…");
            byte[] enc = File.ReadAllBytes(KeyBlobPath);
            Diag($"TryLoadExisting: blob {enc.Length} B, ProtectedData.Unprotect(LocalMachine)…");
            keyDer = ProtectedData.Unprotect(enc, Entropy, DataProtectionScope.LocalMachine);

            Diag("TryLoadExisting: new X509Certificate2(PubCertPath)…");
            var pubCert = new X509Certificate2(PubCertPath);

            Diag($"TryLoadExisting: pubCert.HasPrivateKey={pubCert.HasPrivateKey}, RSA.Create+ImportPkcs8PrivateKey…");
            using var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(keyDer, out _);

            Diag("TryLoadExisting: CopyWithPrivateKey + PFX round-trip…");

            using (var temp = pubCert.CopyWithPrivateKey(rsa))
            {
                byte[] pfx = temp.Export(X509ContentType.Pfx, "");
                _rootWithKey = new X509Certificate2(pfx, "",
                    X509KeyStorageFlags.MachineKeySet
                    | X509KeyStorageFlags.PersistKeySet
                    | X509KeyStorageFlags.Exportable);
                Array.Clear(pfx);
            }

            Log.Info("RootCA", $"Loaded existing root (thumb={_rootWithKey.Thumbprint}, hasKey={_rootWithKey.HasPrivateKey}).");
            Diag($"TryLoadExisting: OK (thumb={_rootWithKey.Thumbprint}, hasKey={_rootWithKey.HasPrivateKey})");
            EnsureInTrustStore(_rootWithKey);
            return true;
        }
        catch (UnauthorizedAccessException ex)
        {
            _lastLoadWasDenied = true;
            Diag($"TryLoadExisting: FAILED UnauthorizedAccessException: {ex.Message}");
            return false;
        }
        catch (Exception ex)
        {
            Diag($"TryLoadExisting: FAILED {ex.GetType().Name}: {ex.Message}");
            Log.Warn("RootCA", $"Load failed: {ex.GetType().Name}: {ex.Message}");
            return false;
        }
        finally
        {
            if (keyDer != null) Array.Clear(keyDer);
        }
    }

    private void GenerateAndInstall()
    {
        Log.Info("RootCA", "Generating a new Malward root (RSA-4096, 10 years)…");
        Diag("Step 1/6: RSA.Create(4096)…");
        using var rsa = RSA.Create(4096);
        Diag("Step 1/6: OK");

        Diag("Step 2/6: CertificateRequest + extensions…");
        var dn = new X500DistinguishedName(
            "CN=Malward Root CA, O=Malward, OU=Network Shield, C=PL");
        var req = new CertificateRequest(dn, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: true, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, critical: false));
        Diag("Step 2/6: OK");

        Diag("Step 3/6: CreateSelfSigned…");
        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter  = DateTimeOffset.UtcNow.AddYears(10);

        using (var ephemeral = req.CreateSelfSigned(notBefore, notAfter))
        {
            byte[] pfx = ephemeral.Export(X509ContentType.Pfx, "");
            _rootWithKey = new X509Certificate2(pfx, "",
                X509KeyStorageFlags.MachineKeySet
                | X509KeyStorageFlags.PersistKeySet
                | X509KeyStorageFlags.Exportable);
            Array.Clear(pfx);
        }
        Diag($"Step 3/6: OK (thumb={_rootWithKey.Thumbprint}, hasKey={_rootWithKey.HasPrivateKey})");

        Diag("Step 4/6: Write public .cer…");
        try
        {
            ResetAclAndDelete(PubCertPath);
            File.WriteAllBytes(PubCertPath, _rootWithKey.Export(X509ContentType.Cert));
            Diag($"Step 4/6: OK ({new FileInfo(PubCertPath).Length} B)");
        }
        catch (Exception ex) { Diag($"Step 4/6: FAILED: {ex.Message}"); throw; }

        Diag("Step 5/6: DPAPI-encrypt key + write blob…");
        byte[] keyDer = rsa.ExportPkcs8PrivateKey();
        try
        {
            byte[] enc;
            try { enc = ProtectedData.Protect(keyDer, Entropy, DataProtectionScope.LocalMachine); }
            catch (Exception ex)
            {
                Diag($"Step 5/6: ProtectedData.Protect FAILED: {ex.GetType().Name}: {ex.Message}");
                throw;
            }
            try
            {
                ResetAclAndDelete(KeyBlobPath);
                File.WriteAllBytes(KeyBlobPath, enc);
                Diag($"Step 5/6: OK (blob={enc.Length} B)");
            }
            catch (Exception ex) { Diag($"Step 5/6: write blob FAILED: {ex.Message}"); throw; }
        }
        finally { Array.Clear(keyDer); }

        try { HardenAcl(KeyBlobPath); HardenAcl(PubCertPath); Diag("ACL hardening: attempted"); }
        catch (Exception ex) { Diag($"ACL hardening warning: {ex.Message}"); }

        Diag("Step 6/6: Install to Trust Store…");
        try
        {
            EnsureInTrustStore(_rootWithKey);
            ResetAclAndDelete(StateFlagPath);
            File.WriteAllText(StateFlagPath, _rootWithKey.Thumbprint);
            Diag($"Step 6/6: OK");
        }
        catch (Exception ex) { Diag($"Step 6/6: FAILED: {ex.Message}"); throw; }

        try
        {
            using var verify = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            verify.Open(OpenFlags.ReadOnly);
            bool found = verify.Certificates.Cast<X509Certificate2>()
                .Any(c => string.Equals(c.Thumbprint, _rootWithKey.Thumbprint, StringComparison.OrdinalIgnoreCase));
            verify.Close();
            Diag($"Trust-store verification: {(found ? "FOUND" : "MISSING!")}");
        }
        catch (Exception ex) { Diag($"Trust-store verification error: {ex.Message}"); }

        Log.Info("RootCA", $"Root generated and installed (thumb={_rootWithKey.Thumbprint}).");
    }

    private static void EnsureInTrustStore(X509Certificate2 root)
    {
        try
        {
            using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);

            var publicOnly = new X509Certificate2(root.Export(X509ContentType.Cert));

            var stale = store.Certificates.Cast<X509Certificate2>()
                .Where(c => string.Equals(c.Subject, publicOnly.Subject, StringComparison.OrdinalIgnoreCase)
                         && !string.Equals(c.Thumbprint, publicOnly.Thumbprint, StringComparison.OrdinalIgnoreCase))
                .ToList();
            foreach (var c in stale)
            {
                try { store.Remove(c); Log.Info("RootCA", $"Removed old root from Trust Store (thumb={c.Thumbprint})."); }
                catch (Exception ex) { Log.Warn("RootCA", $"Trust-store cleanup: {ex.Message}"); }
            }

            bool present = store.Certificates.Cast<X509Certificate2>()
                .Any(c => string.Equals(c.Thumbprint, publicOnly.Thumbprint, StringComparison.OrdinalIgnoreCase));
            if (!present)
            {
                store.Add(publicOnly);
                Log.Info("RootCA", $"Added root to Windows Trust Store (Root\\LocalMachine, thumb={publicOnly.Thumbprint}).");
            }
            store.Close();
        }
        catch (Exception ex)
        {
            Log.Error("RootCA", $"Trust store install failed: {ex.Message}");
        }
    }

    public static void Uninstall()
    {
        try
        {
            string? thumb = null;
            try { thumb = File.Exists(StateFlagPath) ? File.ReadAllText(StateFlagPath).Trim() : null; }
            catch { }
            if (!string.IsNullOrEmpty(thumb))
            {
                using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadWrite);
                var found = store.Certificates.Cast<X509Certificate2>()
                    .Where(c => string.Equals(c.Thumbprint, thumb, StringComparison.OrdinalIgnoreCase)).ToList();
                foreach (var c in found) store.Remove(c);
                store.Close();
            }
            try { if (File.Exists(KeyBlobPath))   File.Delete(KeyBlobPath); }   catch { }
            try { if (File.Exists(PubCertPath))   File.Delete(PubCertPath); }   catch { }
            try { if (File.Exists(StateFlagPath)) File.Delete(StateFlagPath); } catch { }
        }
        catch { }
    }

    private const string SidSystem = "*S-1-5-18";
    private const string SidAdministrators = "*S-1-5-32-544";

    private static bool CanRead(string path)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            return fs.ReadByte() >= 0;
        }
        catch { return false; }
    }

    private static void HardenAcl(string path)
    {
        try
        {
            Run("icacls.exe", $"\"{path}\" /grant:r {SidSystem}:(F) {SidAdministrators}:(F)");
            Run("icacls.exe", $"\"{path}\" /inheritance:r");

            if (!CanRead(path) && RunningAsOwnerAccount())
            {
                Log.Warn("RootCA", $"Hardening made {Path.GetFileName(path)} unreadable — "
                                 + "restoring inherited permissions.");
                Run("icacls.exe", $"\"{path}\" /inheritance:e");
                Run("icacls.exe", $"\"{path}\" /reset /Q");
            }
        }
        catch { }
    }

    private static void ResetAclAndDelete(string path)
    {
        try
        {
            if (!File.Exists(path)) return;

            try { File.SetAttributes(path, FileAttributes.Normal); } catch { }

            try { Run("icacls.exe", $"\"{path}\" /reset /Q"); } catch { }

            try { Run("takeown.exe", $"/F \"{path}\" /A"); } catch { }
            try { Run("icacls.exe", $"\"{path}\" /grant {SidAdministrators}:(F) /Q"); } catch { }

            File.Delete(path);
            Diag($"ResetAclAndDelete: removed stale {Path.GetFileName(path)}");
        }
        catch (Exception ex)
        {
            Diag($"ResetAclAndDelete({Path.GetFileName(path)}): {ex.Message}");
        }
    }

    private static void Run(string exe, string args)
    {
        try
        {
            var psi = new ProcessStartInfo(exe, args)
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(5000);
        }
        catch { }
    }
}
