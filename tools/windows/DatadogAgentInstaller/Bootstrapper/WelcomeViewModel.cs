using CommunityToolkit.Mvvm.Input;
using Microsoft.MinIoC;

namespace Bootstrapper
{
    public class InstallationConfiguration : IInstallationConfiguration
    {
        public InstallType InstallType { get; set; }
    }

    public class WelcomeViewModel : BaseViewModel
    {
        private readonly IInstallationConfiguration _configuration;
        private readonly Container _container;
        public RelayCommand DefaultInstallationCommand { get; }
        public RelayCommand AdvancedInstallationCommand { get; }
        
        public WelcomeViewModel(
            IInstallationConfiguration configuration,
            Container container)
        {
            _configuration = configuration;
            // We can't simply reference INavigationService here
            // since behind the scene it's just MainViewModel and that would
            // create a stack overflow... TODO: Fixme
            _container = container;
            DefaultInstallationCommand = new RelayCommand(InstallWithDefault);
            AdvancedInstallationCommand = new RelayCommand(InstallCustom);
        }

        private void InstallWithDefault()
        {
            _configuration.InstallType = InstallType.Default;
            _container.Resolve<INavigationService>().CurrentPage = _container.Resolve<LicenseAgreementViewModel>();
        }

        private void InstallCustom()
        {
            _configuration.InstallType = InstallType.Advanced;
            _container.Resolve<INavigationService>().CurrentPage = _container.Resolve<LicenseAgreementViewModel>();
        }
    }
}
