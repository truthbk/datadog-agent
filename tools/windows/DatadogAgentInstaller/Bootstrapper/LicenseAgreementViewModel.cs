using System.Windows.Input;
using CommunityToolkit.Mvvm.Input;

namespace Bootstrapper
{
    public class LicenseAgreementViewModel : BaseViewModel
    {
        public RelayCommand BackCommand { get; }
        public RelayCommand NextCommand { get; }

        public string LicenseAgreement { get; }

        private bool _licenseAccepted;
        public bool LicenseAccepted
        {
            get => _licenseAccepted;
            set
            {
                _licenseAccepted = value;
                OnPropertyChanged();
                NextCommand.NotifyCanExecuteChanged();
            }
        }

        public LicenseAgreementViewModel(MainViewModel mainViewModel, WelcomeViewModel welcomeViewModel)
        {
            BackCommand =
                new RelayCommand(() => mainViewModel.CurrentPage = welcomeViewModel);
            NextCommand =
                new RelayCommand(() => mainViewModel.CurrentPage = welcomeViewModel, () => LicenseAccepted);
            using (var licenseStream =
                   //GetType().Assembly.GetManifestResourceStream("Bootstrapper.Resources.Text.License.txt"))
                   GetType().Assembly.GetManifestResourceStream("Bootstrapper.Resources.Text.LICENSE.rtf"))
            {
                using (var reader = new System.IO.StreamReader(licenseStream))
                {
                    LicenseAgreement = reader.ReadToEnd();
                }
            }
        }
    }
}
