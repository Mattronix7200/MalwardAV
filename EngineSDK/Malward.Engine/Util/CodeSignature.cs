using System.Security.Cryptography.X509Certificates;

namespace Malward.Engine.Util;

public static class CodeSignature
{
    public const string ReleaseSubject = "Open Source Developer Jakub Michalski";

    public static bool IsSignedBy(string filePath, string expectedSubject, out string reason)
    {
        reason = "";
        try
        {
            if (!File.Exists(filePath))
            {
                reason = $"{Path.GetFileName(filePath)}: file not found";
                return false;
            }
            if (!SystemFileCheck.HasValidEmbeddedSignature(filePath))
            {
                reason = $"{Path.GetFileName(filePath)}: not signed, or the signature does not match the file";
                return false;
            }

            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath));
            var subject = cert.Subject ?? "";
            if (subject.IndexOf(expectedSubject, StringComparison.OrdinalIgnoreCase) < 0)
            {
                reason = $"{Path.GetFileName(filePath)}: signed by somebody else — {subject}";
                return false;
            }
            return true;
        }
        catch (Exception ex)
        {
            reason = $"{Path.GetFileName(filePath)}: signature could not be read ({ex.GetType().Name})";
            return false;
        }
    }

    public static bool IsSignedAtAll(string filePath)
    {
        try { return SystemFileCheck.HasValidEmbeddedSignature(filePath); }
        catch { return false; }
    }
}
