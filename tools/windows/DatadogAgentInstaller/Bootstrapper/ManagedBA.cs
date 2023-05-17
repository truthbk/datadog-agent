using Microsoft.MinIoC;
using Microsoft.Tools.WindowsInstallerXml.Bootstrapper;

namespace Bootstrapper
{
    // ReSharper disable once InconsistentNaming
    public class ManagedBA : BootstrapperApplication
    {
        /// <summary>
        /// Entry point that is called when the bootstrapper application is ready to run.
        /// </summary>
        protected override void Run()
        {
            var container = new Container();
            container.Register(() => container).AsSingleton();
            container.Register<BootstrapperApplication>(() => this).AsSingleton();

            container.Register<MainViewModel>().AsSingleton();
            container.Register<WelcomeViewModel>();
            container.Register<LicenseAgreementViewModel>();
            container.Register<ConfigurationViewModel>();
            container.Register<InstallationViewModel>();

            container.Register<INavigationService>(() => container.Resolve<MainViewModel>()).AsSingleton();
            container.Register<IInstallationConfiguration, InstallationConfiguration>().AsSingleton();

            new MainView(container).ShowDialog();
            Engine.Quit(0);
        }
    }
}
