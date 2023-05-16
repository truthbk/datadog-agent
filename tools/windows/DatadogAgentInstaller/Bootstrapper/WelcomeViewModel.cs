using System.Windows.Input;
using CommunityToolkit.Mvvm.Input;

namespace Bootstrapper
{
    public class WelcomeViewModel : BaseViewModel
    {
        public RelayCommand DefaultInstallationCommand { get; }
        public RelayCommand AdvancedInstallationCommand { get; }
        

        public WelcomeViewModel(MainViewModel mainViewModel)
        {
            DefaultInstallationCommand =
                new RelayCommand(() => mainViewModel.CurrentPage = new LicenseAgreementViewModel(mainViewModel, this));
            AdvancedInstallationCommand =
                new RelayCommand(() => mainViewModel.CurrentPage = new LicenseAgreementViewModel(mainViewModel, this));

        }
    }
}
