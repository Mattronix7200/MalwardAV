using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Malward.FWManager;

public sealed class FirewallRule
{
    public string Name { get; set; } = "";
    public string? Description { get; set; }
    public string? ApplicationName { get; set; }
    public string? ServiceName { get; set; }
    public int Protocol { get; set; }
    public string? LocalPorts { get; set; }
    public string? RemotePorts { get; set; }
    public string? LocalAddresses { get; set; }
    public string? RemoteAddresses { get; set; }
    public int Direction { get; set; }
    public bool Enabled { get; set; } = true;
    public bool Allow { get; set; }
    public int Profiles { get; set; } = 0x7FFFFFFF;
    public string Grouping { get; set; } = "Malward";
}

public static class FirewallRules
{
    public static List<FirewallRule> List()
    {
        var list = new List<FirewallRule>();
        dynamic? policy = null;
        try
        {
            var t = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            if (t == null) return list;
            policy = Activator.CreateInstance(t)!;
            foreach (var r in policy.Rules)
            {
                try
                {
                    list.Add(new FirewallRule
                    {
                        Name             = r.Name,
                        Description      = r.Description,
                        ApplicationName  = r.ApplicationName,
                        ServiceName      = r.serviceName,
                        Protocol         = r.Protocol,
                        LocalPorts       = r.LocalPorts,
                        RemotePorts      = r.RemotePorts,
                        LocalAddresses   = r.LocalAddresses,
                        RemoteAddresses  = r.RemoteAddresses,
                        Direction        = r.Direction,
                        Enabled          = r.Enabled,
                        Allow            = r.Action == 1,
                        Profiles         = r.Profiles,
                        Grouping         = r.Grouping ?? "",
                    });
                }
                catch {  }
            }
        }
        catch (Exception ex) { Debug.WriteLine("FwRules.List: " + ex.Message); }
        finally
        {
            if (policy != null) try { Marshal.ReleaseComObject(policy); } catch { }
        }
        return list;
    }

    public static HashSet<string> RuleNamesInGroup(string grouping)
    {
        var nazwy = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        dynamic? policy = null;
        try
        {
            var t = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            if (t == null) return nazwy;
            policy = Activator.CreateInstance(t)!;
            foreach (var r in policy.Rules)
            {
                string nazwa = "", grupa = "";
                try { nazwa = (string?)r.Name ?? ""; } catch { }
                try { grupa = (string?)r.Grouping ?? ""; } catch { }
                if (nazwa.Length == 0) continue;
                if (grouping.Length == 0 || string.Equals(grupa, grouping, StringComparison.OrdinalIgnoreCase))
                    nazwy.Add(nazwa);
            }
        }
        catch (Exception ex) { Debug.WriteLine("FwRules.RuleNamesInGroup: " + ex.Message); }
        finally
        {
            if (policy != null) try { Marshal.ReleaseComObject(policy); } catch { }
        }
        return nazwy;
    }

    public static (bool ok, string? error) Add(FirewallRule rule, bool skipIfExists = true)
    {
        dynamic? policy = null;
        dynamic? r = null;
        try
        {
            if (skipIfExists && !string.IsNullOrEmpty(rule.Name)
                && RuleNamesInGroup(rule.Grouping ?? "").Contains(rule.Name))
                return (true, null);

            var tRule = Type.GetTypeFromProgID("HNetCfg.FWRule");
            if (tRule == null) return (false, "Brak HNetCfg.FWRule.");
            r = Activator.CreateInstance(tRule)!;
            r.Name = rule.Name;
            if (!string.IsNullOrEmpty(rule.Description))     r.Description = rule.Description;
            if (!string.IsNullOrEmpty(rule.ApplicationName)) r.ApplicationName = rule.ApplicationName;
            if (!string.IsNullOrEmpty(rule.ServiceName))     r.serviceName = rule.ServiceName;
            r.Protocol  = rule.Protocol;
            if (!string.IsNullOrEmpty(rule.LocalPorts))      r.LocalPorts = rule.LocalPorts;
            if (!string.IsNullOrEmpty(rule.RemotePorts))     r.RemotePorts = rule.RemotePorts;
            if (!string.IsNullOrEmpty(rule.LocalAddresses))  r.LocalAddresses = rule.LocalAddresses;
            if (!string.IsNullOrEmpty(rule.RemoteAddresses)) r.RemoteAddresses = rule.RemoteAddresses;
            r.Direction = rule.Direction;
            r.Enabled   = rule.Enabled;
            r.Action    = rule.Allow ? 1 : 0;
            r.Profiles  = rule.Profiles;
            r.Grouping  = rule.Grouping;

            var tPol = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            policy = Activator.CreateInstance(tPol!)!;
            policy.Rules.Add(r);
            return (true, null);
        }
        catch (Exception ex) { return (false, ex.Message); }
        finally
        {
            if (r != null) try { Marshal.ReleaseComObject(r); } catch { }
            if (policy != null) try { Marshal.ReleaseComObject(policy); } catch { }
        }
    }

    public static (bool ok, string? error) Remove(string name)
    {
        dynamic? policy = null;
        try
        {
            var tPol = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            policy = Activator.CreateInstance(tPol!)!;

            int removed = 0;
            string? lastErr = null;
            try
            {
                policy.Rules.Remove(name);
                removed++;
            }
            catch (Exception ex) { lastErr = ex.Message; }

            try
            {
                foreach (var r in policy.Rules)
                {
                    try { if (r.Name == name) { policy.Rules.Remove(name); removed++; break; } }
                    catch { }
                    finally { try { Marshal.ReleaseComObject(r); } catch { } }
                }
            }
            catch { }
            if (removed > 0) return (true, null);
            return (false, lastErr ?? "Nie znaleziono reguły.");
        }
        catch (Exception ex) { return (false, ex.Message); }
        finally
        {
            if (policy != null) try { Marshal.ReleaseComObject(policy); } catch { }
        }
    }

    public static int DeleteAllMalward(string group = "Malward")
    {
        dynamic? policy = null;
        int count = 0;
        try
        {
            var tPol = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            policy = Activator.CreateInstance(tPol!)!;
            var toDelete = new List<string>();
            foreach (var r in policy.Rules)
            {
                try
                {
                    string g = r.Grouping ?? "";
                    string n = r.Name ?? "";
                    if (g == group || g.Equals(group, StringComparison.OrdinalIgnoreCase))
                        toDelete.Add(n);
                }
                catch { }
                finally { try { Marshal.ReleaseComObject(r); } catch { } }
            }
            foreach (var n in toDelete)
            {
                try { policy.Rules.Remove(n); count++; } catch { }
            }
        }
        catch { }
        finally { if (policy != null) try { Marshal.ReleaseComObject(policy); } catch { } }
        return count;
    }

    public static (bool ok, string? error) SetEnabled(string name, bool enabled)
    {
        dynamic? policy = null;
        try
        {
            var tPol = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            policy = Activator.CreateInstance(tPol!)!;
            foreach (var r in policy.Rules)
            {
                try
                {
                    if (r.Name == name) { r.Enabled = enabled; return (true, null); }
                }
                catch { }
                finally { try { Marshal.ReleaseComObject(r); } catch { } }
            }
            return (false, "Nie znaleziono reguły.");
        }
        catch (Exception ex) { return (false, ex.Message); }
        finally { if (policy != null) try { Marshal.ReleaseComObject(policy); } catch { } }
    }

    public static (bool ok, string? error) BlockProgram(string applicationPath, string ruleName)
    {
        return Add(new FirewallRule
        {
            Name = ruleName,
            ApplicationName = applicationPath,
            Description = $"Malward — blokada dla {Path.GetFileName(applicationPath)}",
            Protocol = 256,
            Direction = 2,
            Allow = false,
            Enabled = true,
        });
    }

    public static (int created, string? error) BlockOrAllowFolder(
        string folder, string namePrefix, bool allow, int direction)
    {
        if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder))
            return (0, "Folder nie istnieje.");
        int created = 0;
        string? lastErr = null;
        IEnumerable<string> exes;
        try { exes = Directory.EnumerateFiles(folder, "*.exe", SearchOption.AllDirectories); }
        catch (Exception ex) { return (0, "Nie mogę przejrzeć folderu: " + ex.Message); }

        foreach (var exe in exes)
        {
            string name = $"{namePrefix} — {Path.GetFileName(exe)}";

            if (name.Length > 250) name = name.Substring(0, 250);
            var (ok, err) = Add(new FirewallRule
            {
                Name = name,
                ApplicationName = exe,
                Description = $"Malward — {(allow ? "allow" : "block")} folder rule: {folder}",
                Protocol = 256,
                Direction = direction,
                Allow = allow,
                Enabled = true,
                Grouping = "Malward-Wildcard",
            });
            if (ok) created++;
            else lastErr = err;
        }
        return (created, created == 0 ? lastErr : null);
    }

    private static readonly object _lolbinGate = new();

    public static (int created, int skipped, string? error) AddLolbinHardening(bool extended = false)
    {
        lock (_lolbinGate) return AddLolbinHardeningCore(extended);
    }

    private static (int created, int skipped, string? error) AddLolbinHardeningCore(bool extended)
    {
        var recommended = new[]
        {
            "powershell.exe", "powershell_ise.exe", "pwsh.exe",
            "wscript.exe", "cscript.exe",

            "mshta.exe", "hh.exe",

            "regsvr32.exe", "rundll32.exe", "regsvcs.exe", "regasm.exe",

            "bitsadmin.exe", "certutil.exe", "esentutl.exe", "certreq.exe",

            "msbuild.exe", "installutil.exe", "ieexec.exe",
            "ilasm.exe", "jsc.exe",

            "forfiles.exe", "msxsl.exe", "pcalua.exe",

            "wmic.exe", "diskshadow.exe",
        };
        var extendedExtras = new[]
        {
            "print.exe", "PrintBrm.exe",

            "appvlp.exe", "atbroker.exe", "cmdkey.exe",
            "control.exe", "expand.exe", "extexport.exe", "extrac32.exe",
            "findstr.exe", "ftp.exe", "gpscript.exe",

            "mavinject.exe", "mmc.exe", "msconfig.exe",
            "odbcconf.exe", "pcwrun.exe", "presentationhost.exe",
            "regedit.exe", "register-cimprovider.exe",
            "scriptrunner.exe", "syncappvpublishingserver.exe", "verclsid.exe",
            "winrs.exe", "xwizard.exe",

            "msdt.exe", "msiexec.exe",
        };
        var lolbins = extended
            ? recommended.Concat(extendedExtras).Distinct(StringComparer.OrdinalIgnoreCase).ToArray()
            : recommended;
        string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var sys32 = Path.Combine(winDir, "System32");
        var sysWow = Path.Combine(winDir, "SysWOW64");

        string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var roots = new[]
        {
            sys32, sysWow,
            Path.Combine(sys32, "WindowsPowerShell", "v1.0"),
            Path.Combine(sysWow, "WindowsPowerShell", "v1.0"),
            winDir,
            string.IsNullOrEmpty(pf) ? "" : Path.Combine(pf, "PowerShell", "7"),
        };

        var existing = RuleNamesInGroup("Malward-LOLBin");

        int created = 0, skipped = 0;
        string? lastErr = null;
        foreach (var bin in lolbins)
        {
            foreach (var root in roots)
            {
                if (root.Length == 0) continue;
                var full = Path.Combine(root, bin);
                if (!File.Exists(full)) { skipped++; continue; }
                string name = $"Malward LOLBin block — {bin} ({Path.GetFileName(root)})";
                if (!existing.Add(name)) { skipped++; continue; }
                var (ok, err) = Add(skipIfExists: false, rule: new FirewallRule
                {
                    Name = name,
                    ApplicationName = full,
                    Description = "Malward — LOLBin hardening (block outbound)",
                    Protocol = 256,
                    Direction = 2,
                    Allow = false,
                    Enabled = true,
                    Grouping = "Malward-LOLBin",
                });
                if (ok) created++; else { skipped++; lastErr = err; }
            }
        }
        return (created, skipped, created == 0 ? lastErr : null);
    }

    public static int DeleteAllMalwardPrefixed()
    {
        dynamic? policy = null;
        int count = 0;
        try
        {
            var tPol = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            policy = Activator.CreateInstance(tPol!)!;
            var toDelete = new List<string>();
            foreach (var r in policy.Rules)
            {
                try
                {
                    string g = r.Grouping ?? "";
                    string n = r.Name ?? "";

                    bool self = g.Equals("Malward-Self", StringComparison.OrdinalIgnoreCase)
                             || n.StartsWith("Malward Self-Allow", StringComparison.OrdinalIgnoreCase);
                    if (!self && g.StartsWith("Malward", StringComparison.OrdinalIgnoreCase))
                        toDelete.Add(n);
                }
                catch { }
                finally { try { Marshal.ReleaseComObject(r); } catch { } }
            }
            foreach (var n in toDelete)
            {
                try { policy.Rules.Remove(n); count++; } catch { }
            }
        }
        catch { }
        finally { if (policy != null) try { Marshal.ReleaseComObject(policy); } catch { } }
        return count;
    }
}
