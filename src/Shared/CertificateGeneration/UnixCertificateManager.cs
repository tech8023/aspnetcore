// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
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
            using var program = Process.Start("openssl", $"verify {tempCertificate}");
            program.WaitForExit();
            return program.ExitCode == 0;
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

        var tempCertificate = Path.Combine(Path.GetTempPath(), $"aspnetcore-localhost-{certificate.Thumbprint}.crt");
        File.WriteAllText(tempCertificate, certificate.ExportCertificatePem());

        var openSSLDirectory = GetOpenSSLDirectory();

        using var copy = Process.Start("sudo", $"cp {tempCertificate} {openSSLDirectory}");
        copy.WaitForExit();

        if (copy.ExitCode == -1)
        {
            return;
        }

        using var rehash = Process.Start("sudo", $"c_rehash");
        rehash.WaitForExit();

        if (rehash.ExitCode != 0)
        {
            return;
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

        return true;
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

    private static ProgramOutput RunScriptAndCaptureOutput(string name, string arguments, [StringSyntax("Regex")] string regex, string captureName)
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

            File.Delete(installedCertificate);
            using var program = Process.Start("sudo", $"c_rehash");
            program.WaitForExit();
        }
        catch (Exception)
        {
            throw;
        }
        finally
        {
            if (File.Exists(installedCertificate))
            {
                File.Delete(installedCertificate);
            }
        }
    }

    protected override IList<X509Certificate2> GetCertificatesToRemove(StoreName storeName, StoreLocation storeLocation)
    {
        return ListCertificates(StoreName.My, StoreLocation.CurrentUser, isValid: false, requireExportable: false);
    }

    private sealed record ProgramOutput(int ExitCode, string Output);
}
