using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Malward.NetworkScanner;

public sealed class LeafCertCache
{
    private readonly RootCaManager _root;
    private readonly ConcurrentDictionary<string, X509Certificate2> _cache
        = new(StringComparer.OrdinalIgnoreCase);

    private const int LeafKeySize = 2048;
    private static readonly TimeSpan LeafValidity = TimeSpan.FromDays(7);
    private const int MaxCacheSize = 512;

    public LeafCertCache(RootCaManager root) => _root = root;

    public X509Certificate2? GetOrCreate(string host)
    {
        var rootWithKey = _root.RootWithKey;
        if (rootWithKey == null) return null;

        host = (host ?? "").Trim().ToLowerInvariant();
        if (host.Length == 0 || host.Length > 253) return null;

        if (_cache.TryGetValue(host, out var existing))
        {
            if (existing.NotAfter > DateTime.UtcNow.AddMinutes(5)) return existing;
            _cache.TryRemove(host, out _);
            try { existing.Dispose(); } catch { }
        }

        var leaf = Generate(host, rootWithKey);
        if (leaf == null) return null;

        if (_cache.Count >= MaxCacheSize)
        {
            var victim = _cache.Keys.FirstOrDefault();
            if (victim != null && _cache.TryRemove(victim, out var old))
                try { old.Dispose(); } catch { }
        }

        _cache[host] = leaf;
        return leaf;
    }

    private static X509Certificate2? Generate(string host, X509Certificate2 issuer)
    {
        try
        {
            using var rsa = RSA.Create(LeafKeySize);
            var req = new CertificateRequest(
                $"CN={host}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName(host);
            req.CertificateExtensions.Add(san.Build());

            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(
                certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
            req.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true));
            req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.1")  }, critical: false));
            req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, critical: false));

            byte[] serial = new byte[10];
            RandomNumberGenerator.Fill(serial);
            serial[0] &= 0x7F;

            var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
            var notAfter  = DateTimeOffset.UtcNow.Add(LeafValidity);
            var leafNoKey = req.Create(issuer, notBefore, notAfter, serial);

            using var ephemeral = leafNoKey.CopyWithPrivateKey(rsa);
            byte[] pfx = ephemeral.Export(X509ContentType.Pfx, "");
            var persistent = new X509Certificate2(pfx, "",
                X509KeyStorageFlags.MachineKeySet
                | X509KeyStorageFlags.PersistKeySet
                | X509KeyStorageFlags.Exportable);
            Array.Clear(pfx);
            return persistent;
        }
        catch (Exception ex)
        {
            Log.Warn("LeafCert", $"Generate {host} failed: {ex.GetType().Name}: {ex.Message}");
            return null;
        }
    }
}
