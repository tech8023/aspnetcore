// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace Microsoft.AspNetCore.Certificates.Generation;

internal sealed class UnixCertificateManager : CertificateManager
{
    public UnixCertificateManager()
    {
    }

    internal UnixCertificateManager(string subject, int version)
        : base(subject, version)
    {
    }

    public override bool IsTrusted(X509Certificate2 certificate)
    {
        var tempCertificate = Path.Combine(Path.GetTempPath(), $"aspnetcore-localhost-{certificate.Thumbprint}.crt");
        try
        {
            File.WriteAllText(tempCertificate, certificate.ExportCertificatePem());
            var program = RunScriptAndCaptureOutput("openssl", $"verify {tempCertificate}");
            if (program.ExitCode != 0)
            {
                return false;
            }
        }
        catch (Exception)
        {
            throw;
        }
        finally
        {
            if (File.Exists(tempCertificate))
            {
                File.Delete(tempCertificate);
            }
        }

        if (!IsTrustedInNssDb(GetFirefoxCertificateDbDirectory(), certificate))
        {
            return false;
        }

        if (!IsTrustedInNssDb(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".pki/nssdb"), certificate))
        {
            return false;
        }

        return true;
    }

    private static bool IsTrustedInNssDb(string dbPath, X509Certificate2 certificate)
    {
        if (dbPath != null)
        {
            var (exitCode, output) = RunScriptAndCaptureOutput(
                "certutil",
                $"-L -d sql:{dbPath}",
                $"(?<certificate>aspnetcore-localhost-{certificate.Thumbprint[0..6]})",
                "certificate");

            return exitCode == 0 && !string.IsNullOrEmpty(output);
        }

        return false;
    }

    protected override X509Certificate2 SaveCertificateCore(X509Certificate2 certificate, StoreName storeName, StoreLocation storeLocation)
    {
        var export = certificate.Export(X509ContentType.Pkcs12, "");
        certificate.Dispose();
        certificate = new X509Certificate2(export, "", X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
        Array.Clear(export, 0, export.Length);

        using (var store = new X509Store(storeName, storeLocation))
        {
            store.Open(OpenFlags.ReadWrite);
            store.Add(certificate);
            store.Close();
        };

        return certificate;
    }

    internal override CheckCertificateStateResult CheckCertificateState(X509Certificate2 candidate, bool interactive)
    {
        // Return true as we don't perform any check.
        return new CheckCertificateStateResult(true, null);
    }

    internal override void CorrectCertificateState(X509Certificate2 candidate)
    {
        // Do nothing since we don't have anything to check here.
    }

    protected override bool IsExportable(X509Certificate2 c) => true;

    protected override void TrustCertificateCore(X509Certificate2 certificate)
    {
        if (!CheckPrerequisites())
        {
            return;
        }

        var certificateName = $"aspnetcore-localhost-{certificate.Thumbprint}.crt";
        var tempCertificate = Path.Combine(Path.GetTempPath(), certificateName);
        File.WriteAllText(tempCertificate, certificate.ExportCertificatePem());

        var openSSLDirectory = Path.Combine(GetOpenSSLDirectory(), "certs");

        var (copyExitCode, _) = RunScriptAndCaptureOutput("sudo", $"cp {tempCertificate} {openSSLDirectory}");
        if (copyExitCode == -1)
        {
            return;
        }

        var (exitCode, _) = RunScriptAndCaptureOutput("sudo", $"c_rehash");
        if (exitCode != 0)
        {
            return;
        }

        var firefoxDbPath = GetFirefoxCertificateDbDirectory();
        TrustCertificateInNssDb(firefoxDbPath, certificate, tempCertificate);
        TrustCertificateInNssDb(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".pki/nssdb"), certificate, tempCertificate);
    }

    private static void TrustCertificateInNssDb(string dbPath, X509Certificate2 certificate, string certificatePath)
    {
        if (dbPath != null)
        {
            RunScriptAndCaptureOutput(
                "certutil",
                $"-A -d sql:{dbPath} -t \"C,,\" -n aspnetcore-localhost-{certificate.Thumbprint[0..6]} -i {certificatePath}");
        }
    }

    private static string GetFirefoxCertificateDbDirectory()
    {
        return EnumerateIfExistsInUserProfile(".mozilla/firefox/", "*.default-release") ??
                EnumerateIfExistsInUserProfile("snap/firefox/common/.mozilla/firefox/", "*.default-release") ??
                EnumerateIfExistsInUserProfile("snap/firefox/common/.mozilla/firefox/", "*.default");

        static string EnumerateIfExistsInUserProfile(string subpath, string pattern)
        {
            var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), subpath);
            if (!Directory.Exists(directory))
            {
                return null;
            }

            return Directory.EnumerateDirectories(directory, pattern).SingleOrDefault();
        }
    }

    private static string GetOpenSSLDirectory()
    {
        var (directoryExitCode, openSSLDirectory) = RunScriptAndCaptureOutput(
            "openssl",
            "version -d",
            "OPENSSLDIR: \"(?<libpath>.+?)\"",
            "libpath");

        if (directoryExitCode != 0 || string.IsNullOrEmpty(openSSLDirectory))
        {
            return null;
        }

        return openSSLDirectory;
    }

    private static bool CheckPrerequisites()
    {
        if (!IsSupportedOpenSslVersion())
        {
            return false;
        }

        if (!IsCertUtilAvailable())
        {
            return false;
        }

        return true;
    }

    private static bool IsCertUtilAvailable()
    {
        try
        {
            var (certUtilExitCode, _) = RunScriptAndCaptureOutput("certutil", "");
            return certUtilExitCode != 127;
        }
        catch (Exception)
        {
            return false;
            throw;
        }
    }

    private static bool IsSupportedOpenSslVersion()
    {
        var (exitCode, output) = RunScriptAndCaptureOutput(
            "openssl",
            "version",
            @"OpenSSL (?<version>\d\.\d.\d(\.\d\w)?)",
            "version");

        if (exitCode != 0 || string.IsNullOrEmpty(output))
        {
            return false;
        }

        var version = output.Split('.');
        var major = version[0];
        var letter = version.Length > 3 ? version[3][1] : 'a';
        return int.Parse(major, CultureInfo.InvariantCulture) >= 3 || letter >= 'k';
    }

    private static ProgramOutput RunScriptAndCaptureOutput(string name, string arguments, [StringSyntax("Regex")] string regex = null, string captureName = null)
    {
        var processInfo = new ProcessStartInfo(name, arguments)
        {
            RedirectStandardOutput = true,
        };
        using var process = Process.Start(processInfo);
        process.WaitForExit();
        var output = process.StandardOutput.ReadToEnd();
        if (process.ExitCode == -1)
        {
            return new(process.ExitCode, null);
        }

        if (regex == null || captureName == null)
        {
            return new(process.ExitCode, output);
        }

        var versionMatch = Regex.Match(output, regex);
        if (!versionMatch.Success)
        {
            return new(process.ExitCode, null);
        }

        return new(process.ExitCode, versionMatch.Groups[captureName].Value);
    }

    protected override void RemoveCertificateFromTrustedRoots(X509Certificate2 certificate)
    {
        var installedCertificate = Path.Combine(GetOpenSSLDirectory(), "certs", $"aspnetcore-localhost-{certificate.Thumbprint}.crt");
        try
        {
            if (!File.Exists(installedCertificate))
            {
                return;
            }

            RunScriptAndCaptureOutput("sudo", $"rm {installedCertificate}");
            RunScriptAndCaptureOutput("sudo", $"c_rehash");
        }
        catch (Exception)
        {
            throw;
        }

        try
        {
            RemoveCertificateFromNssDb(GetFirefoxCertificateDbDirectory(), certificate);
            RemoveCertificateFromNssDb(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".pki/nssdb"), certificate);
        }
        catch (Exception)
        {
            throw;
        }
    }

    private static void RemoveCertificateFromNssDb(string dbPath, X509Certificate2 certificate)
    {
        if (dbPath != null)
        {
            RunScriptAndCaptureOutput(
                "certutil",
                $"-D -d sql:{dbPath} -n aspnetcore-localhost-{certificate.Thumbprint[0..6]}");
        }
    }

    protected override IList<X509Certificate2> GetCertificatesToRemove(StoreName storeName, StoreLocation storeLocation)
    {
        return ListCertificates(StoreName.My, StoreLocation.CurrentUser, isValid: false, requireExportable: false);
    }

    private sealed record ProgramOutput(int ExitCode, string Output);
}
