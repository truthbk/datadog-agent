using System;
using System.IO;
using Bootstrapper;
using Datadog.CustomActions;
using WixSharp;
using WixSetup.Datadog;
using WixSharp.Bootstrapper;

namespace WixSetup
{
    internal abstract class Program
    {
        private static string BuildMsi(string version = null, bool rebuild = true)
        {
            // Print this line during the CI build so we can check that the CiInfo class picked up the
            // %PACKAGE_VERSION% environment variable correctly.
            Console.WriteLine($"Building MSI installer for Datadog Agent version {CiInfo.PackageVersion}");
            var project = new AgentInstaller(version)
                .ConfigureProject();

            var msiPath = Path.Combine(project.OutDir, $"{project.OutFileName}.msi");
            // In debug mode, don't rebuild the MSI every time
            if (System.IO.File.Exists(msiPath) && !rebuild)
            {
                return msiPath;
            }

#if DEBUG
            // Save a copy of the WXS for analysis since WixSharp deletes it after it's done generating the MSI.
            project.WixSourceSaved += path =>
            {
                System.IO.File.Copy(path, "wix/WixSetup.g.wxs", overwrite: true);
            };
#endif

            return project.BuildMsi();
        }

        private static void BuildBootstrapper(string agentMsi)
        {
            var bootstrapper =
                new Bundle("Datadog Agent",
                    new MsiPackage(agentMsi)
                    {
                        Id = "DatadogAgent"
                    }
                );
            bootstrapper.Version = new Version("1.0.0.0");
            bootstrapper.UpgradeCode = new Guid("F3B0657C-2C48-4F25-BEB7-654D4A0CF5FE");
            bootstrapper.Include(WixExtension.Util);
            bootstrapper.Application = new ManagedBootstrapperApplication(typeof(ManagedBA).Assembly.Location, "BootstrapperCore.config");
            bootstrapper.PreserveTempFiles = true;
            // Name of the WXS, without the extension
            bootstrapper.OutFileName = "DatadogAgentBootstrapper";
            // Name of the EXE
            bootstrapper.Build("DatadogAgentInstaller.exe");
        }

        private static void Main()
        {
            Compiler.LightOptions += "-sval -reusecab -cc \"cabcache\"";
            // ServiceConfig functionality is documented in the Windows Installer SDK to "not [work] as expected." Consider replacing ServiceConfig with the WixUtilExtension ServiceConfig element.
            Compiler.CandleOptions += "-sw1150";

#if false
            // Useful to produce multiple versions of the installer for testing.
            BuildMsi("7.43.0~rc.3+git.485.14b9337");
#endif
            BuildBootstrapper(BuildMsi(rebuild: false));
        }
    }

}
