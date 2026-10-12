using System.Collections.Concurrent;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Malward.Engine.Cloud;

public static class CertPinning
{
    private static readonly ConcurrentDictionary<string, byte> Reported = new();

    public static bool Validate(X509Certificate2? cert, SslPolicyErrors errors, string? pin,
                                Action<string>? log = null)
    {
        var expected = Normalize(pin);
        if (cert is null)
        {
            log?.Invoke("TLS: the server presented no certificate");
            return false;
        }

        if (expected.Length == 0)
        {
            if (errors == SslPolicyErrors.None) return true;
            log?.Invoke($"TLS: no pin configured and the chain is not valid ({errors})");
            return false;
        }

        var actual = Convert.ToHexString(SHA256.HashData(cert.RawData)).ToLowerInvariant();
        if (string.Equals(actual, expected, StringComparison.Ordinal)) return true;

        if (errors == SslPolicyErrors.None)
        {
            if (Reported.TryAdd(actual, 0))

                log?.Invoke("TLS: the certificate does not match the pin, but this machine trusts "
                            + $"its issuer — the connection is being inspected by: {cert.Issuer}. "
                            + "Proceeding; if that name is not something you installed, stop and "
                            + "investigate.");
            return true;
        }

        if (Reported.TryAdd(actual, 0))
            log?.Invoke($"TLS: certificate pin mismatch and an untrusted chain ({errors}). "
                        + $"expected={expected} actual={actual} issuer={cert.Issuer} — "
                        + "either the server certificate was renewed and the pin was not updated, "
                        + "or this is not our server. Connection refused.");
        return false;
    }

    public static HttpClientHandler Handler(string? pin, Action<string>? log = null)
        => new()
        {
            ServerCertificateCustomValidationCallback = (_, cert, _, errors) =>
                Validate(cert, errors, pin, log),
        };

    public static string Normalize(string? pin)
        => (pin ?? string.Empty).Replace(":", "").Replace(" ", "").Trim().ToLowerInvariant();
}
