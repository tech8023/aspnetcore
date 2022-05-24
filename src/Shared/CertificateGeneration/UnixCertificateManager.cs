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

        if (!IsTrustedInNssDb(GetEdgeAndChromeDbDirectory(), certificate))
        {
            return false;
        }

        return true;
    }

    private static string GetEdgeAndChromeDbDirectory()
    {
        var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".pki/nssdb");
        return Directory.Exists(directory) ? directory : null;
    }

    private static bool IsTrustedInNssDb(string dbPath, X509Certificate2 certificate)
    {
        if (dbPath != null)
        {
            var (exitCode, output, _) = RunScriptAndCaptureOutput(
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

        var openSSLDirectory = GetOpenSSLDirectory();
        if (openSSLDirectory != null)
        {
            var openSSLCertsDirectory = Path.Combine(openSSLDirectory, "certs");
            var (copyExitCode, _, copyError) = RunScriptAndCaptureOutput("sudo", $"cp {tempCertificate} {openSSLCertsDirectory}");
            if (copyExitCode != 0)
            {
                Log.UnixCopyCertificateToOpenSSLCertificateStoreError(copyError);
                return;
            }

            var (exitCode, _, rehashError) = RunScriptAndCaptureOutput("sudo", $"c_rehash");
            if (exitCode != 0)
            {
                Log.UnixTrustCertificateFromRootStoreOpenSSLRehashFailed(rehashError);
                return;
            }
        }

        try
        {
            var firefoxDbPath = GetFirefoxCertificateDbDirectory();
            if (firefoxDbPath != null)
            {
                if (!TryTrustCertificateInNssDb(firefoxDbPath, certificate, tempCertificate, out var command, out var error))
                {
                    Log.UnixTrustCertificateFirefoxRootStoreError($"Failed to run the command '{command}'.{Environment.NewLine}{error}");
                }
            }
        }
        catch (Exception ex)
        {
            Log.UnixTrustCertificateFirefoxRootStoreError(ex.Message);
            throw;
        }

        try
        {
            var chromeAndEdgeDbPath = GetEdgeAndChromeDbDirectory();
            if (chromeAndEdgeDbPath != null)
            {
                if (!TryTrustCertificateInNssDb(chromeAndEdgeDbPath, certificate, tempCertificate, out var command, out var error))
                {
                    Log.UnixTrustCertificateCommonEdgeChromeRootStoreError($"Failed to run the command '{command}'.{Environment.NewLine}{error}");
                }
            }
        }
        catch (Exception ex)
        {
            Log.UnixTrustCertificateCommonEdgeChromeRootStoreError(ex.Message);
            throw;
        }
    }

    private static bool TryTrustCertificateInNssDb(string dbPath, X509Certificate2 certificate, string certificatePath, out string command, out string error)
    {
        command = null;
        error = null;
        if (dbPath != null)
        {
            var result = RunScriptAndCaptureOutput(
                "certutil",
                $"-A -d sql:{dbPath} -t \"C,,\" -n aspnetcore-localhost-{certificate.Thumbprint[0..6]} -i {certificatePath}");
            if (result.ExitCode != 0)
            {
                command = "certutil " + $"-D -d sql:{dbPath} -n aspnetcore-localhost-{certificate.Thumbprint[0..6]}";
                error = result.Output + Environment.NewLine + result.Error;
                return false;
            }
        }

        return true;
    }

    private static string GetFirefoxCertificateDbDirectory()
    {
        return EnumerateIfExistsInUserProfile(".mozilla/firefox/", "*.default-release") ??
                EnumerateIfExistsInUserProfile("snap/firefox/common/.mozilla/firefox/", "*.default-release") ??
                EnumerateIfExistsInUserProfile("snap/firefox/common/.mozilla/firefox/", "*.default");

    }

    private static string EnumerateIfExistsInUserProfile(string subpath, string pattern)
    {
        var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), subpath);
        if (!Directory.Exists(directory))
        {
            return null;
        }

        return Directory.EnumerateDirectories(directory, pattern).SingleOrDefault();
    }

    private static string GetOpenSSLDirectory()
    {
        var (directoryExitCode, openSSLDirectory, directoryError) = RunScriptAndCaptureOutput(
            "openssl",
            "version -d",
            "OPENSSLDIR: \"(?<libpath>.+?)\"",
            "libpath");

        if (directoryExitCode != 0 || string.IsNullOrEmpty(openSSLDirectory))
        {
            Log.UnixFailedToLocateOpenSSLDirectory(directoryError);
            return null;
        }
        else
        {
            Log.UnixOpenSSLDirectoryLocatedAt(openSSLDirectory);
        }

        return openSSLDirectory;
    }

    private static bool CheckPrerequisites()
    {
        if (!IsSupportedOpenSslVersion(out var version))
        {
            Log.OldOpenSSLVersion(version);
            return false;
        }
        else
        {
            Log.ValidOpenSSLVersion(version);
        }

        if (!IsCertUtilAvailable(out var error))
        {
            Log.MissingCertUtil(error);
            return false;
        }
        else
        {
            Log.FoundCertUtil();
        }

        return true;
    }

    private static bool IsCertUtilAvailable(out string error)
    {
        try
        {
            var (certUtilExitCode, _, certUtilAvailableError) = RunScriptAndCaptureOutput("certutil", "");
            error = certUtilAvailableError;
            return certUtilExitCode != 127;
        }
        catch (Exception ex)
        {
            error = ex.ToString();
            return false;
        }
    }

    private static bool IsSupportedOpenSslVersion(out string output)
    {
        (var exitCode, output, _) = RunScriptAndCaptureOutput(
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
            RedirectStandardError = true,
        };
        using var process = Process.Start(processInfo);
        process.WaitForExit();
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        if (process.ExitCode == -1)
        {
            return new(process.ExitCode, null, error);
        }

        if (regex == null || captureName == null)
        {
            return new(process.ExitCode, output, null);
        }

        var versionMatch = Regex.Match(output, regex);
        if (!versionMatch.Success)
        {
            return new(process.ExitCode, null, null);
        }

        return new(process.ExitCode, versionMatch.Groups[captureName].Value, null);
    }

    protected override void RemoveCertificateFromTrustedRoots(X509Certificate2 certificate)
    {
        var installedCertificate = Path.Combine(GetOpenSSLDirectory(), "certs", $"aspnetcore-localhost-{certificate.Thumbprint}.crt");
        try
        {
            Log.UnixRemoveCertificateFromRootStoreStart();
            if (!File.Exists(installedCertificate))
            {
                Log.UnixRemoveCertificateFromRootStoreNotFound();
            }
            else
            {
                var rmResult = RunScriptAndCaptureOutput("sudo", $"rm {installedCertificate}");
                if (rmResult.ExitCode != 0)
                {
                    Log.UnixRemoveCertificateFromRootStoreFailedtoDeleteFile(installedCertificate, rmResult.Error);
                }
            }

            var reHashResult = RunScriptAndCaptureOutput("sudo", $"c_rehash");
            if (reHashResult.ExitCode != 0)
            {
                Log.UnixRemoveCertificateFromRootStoreOpenSSLRehashFailed(reHashResult.Error);
            }
            Log.UnixRemoveCertificateFromRootStoreEnd();
        }
        catch (Exception)
        {
            throw;
        }

        try
        {
            var firefoxDbPath = GetFirefoxCertificateDbDirectory();
            if (!string.IsNullOrEmpty(firefoxDbPath))
            {
                Log.UnixFirefoxProfileNotFound("~/.mozilla/firefox/", "snap/firefox/common/.mozilla/firefox/");
            }
            else
            {
                Log.UnixFirefoxProfileFound(firefoxDbPath);
                if (!TryRemoveCertificateFromNssDb(firefoxDbPath, certificate, out var command, out var error))
                {
                    Log.UnixRemoveCertificateFromFirefoxRootStoreError($"Failed to run the command '{command}'.{Environment.NewLine}{error}");
                }

            }
        }
        catch (Exception ex)
        {
            Log.UnixRemoveCertificateFromFirefoxRootStoreError(ex.Message);
        }

        try
        {
            var edgeAndChromeDbPath = GetEdgeAndChromeDbDirectory();
            if (!string.IsNullOrEmpty(edgeAndChromeDbPath))
            {
                Log.UnixCommonChromeAndEdgeCertificateDbNotFound("~/.pki/nssdb/");
            }
            else
            {
                Log.UnixCommonChromeAndEdgeCertificateDbFound(edgeAndChromeDbPath);
                if (!TryRemoveCertificateFromNssDb(edgeAndChromeDbPath, certificate, out var command, out var error))
                {
                    Log.UnixRemoveCertificateFromFirefoxRootStoreError($"Failed to run the command '{command}'.{Environment.NewLine}{error}");
                }
            }
        }
        catch (Exception ex)
        {
            Log.UnixRemoveCertificateFromCommonEdgeChromeRootStoreError(ex.Message);
        }

        Log.UnixRemoveCertificateFromRootStoreEnd();
    }

    private static bool TryRemoveCertificateFromNssDb(string dbPath, X509Certificate2 certificate, out string command, out string error)
    {
        command = null;
        error = null;
        if (dbPath != null)
        {
            var result = RunScriptAndCaptureOutput(
                "certutil",
                $"-D -d sql:{dbPath} -n aspnetcore-localhost-{certificate.Thumbprint[0..6]}");
            if (result.ExitCode != 0)
            {
                command = "certutil " + $"-D -d sql:{dbPath} -n aspnetcore-localhost-{certificate.Thumbprint[0..6]}";
                error = result.Output + Environment.NewLine + result.Error;
                return false;
            }
        }

        return true;
    }

    protected override IList<X509Certificate2> GetCertificatesToRemove(StoreName storeName, StoreLocation storeLocation)
    {
        return ListCertificates(StoreName.My, StoreLocation.CurrentUser, isValid: false, requireExportable: false);
    }

    private sealed record ProgramOutput(int ExitCode, string Output, string Error);
}
