using System.Windows.Input;
using CommunityToolkit.Mvvm.Input;
using Microsoft.MinIoC;
using Microsoft.Tools.WindowsInstallerXml.Bootstrapper;
using WixSharp;

namespace Bootstrapper
{
    public interface INavigationService
    {
        BaseViewModel CurrentPage { get; set; }
    }

    public class ConfigurationViewModel : BaseViewModel
    {
        public RelayCommand BackCommand { get; }
        public RelayCommand NextCommand { get; }

        public ConfigurationViewModel(
            INavigationService navigationService,
            Container container)
        {
            BackCommand =
                new RelayCommand(() =>
                {
                    navigationService.CurrentPage = container.Resolve<LicenseAgreementViewModel>();

                });
            NextCommand =
                new RelayCommand(() =>
                {
                    navigationService.CurrentPage = container.Resolve<InstallationViewModel>();

                });
        }
    }

    public class InstallationViewModel : BaseViewModel
    {
        private readonly BootstrapperApplication _bootstrapper;

        public InstallationViewModel(INavigationService navigationService, BootstrapperApplication bootstrapper)
        {
            _bootstrapper = bootstrapper;
            _bootstrapper.Error += OnError;
            _bootstrapper.ApplyComplete += OnApplyComplete;
            _bootstrapper.PlanComplete += OnPlanComplete;

            //IsBusy = true;
            _bootstrapper.Engine.Plan(LaunchAction.Install);
        }

        private void OnError(object sender, ErrorEventArgs e)
        {
            
        }

        /// <summary>
        /// Method that gets invoked when the Bootstrapper ApplyComplete event is fired.
        /// This is called after a bundle installation has completed. Make sure we updated the view.
        /// </summary>
        void OnApplyComplete(object sender, ApplyCompleteEventArgs e)
        {
            //IsBusy = false;
            //InstallEnabled = false;
            //UninstallEnabled = false;
        }

        /// <summary>
        /// Method that gets invoked when the Bootstrapper PlanComplete event is fired.
        /// If the planning was successful, it instructs the Bootstrapper Engine to
        /// install the packages.
        /// </summary>
        void OnPlanComplete(object sender, PlanCompleteEventArgs e)
        {
            if (e.Status >= 0)
            {
                _bootstrapper.Engine.Apply(System.IntPtr.Zero);
            }
        }
    }

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

        public string NextButtonLabel
        {
            get;
        }

        public LicenseAgreementViewModel(
            INavigationService navigationService,
            IInstallationConfiguration configuration,
            Container container)
        {
            NextButtonLabel = configuration.InstallType == InstallType.Default ? "Install" : "Next";
            BackCommand =
                new RelayCommand(() => navigationService.CurrentPage = container.Resolve<WelcomeViewModel>());
            NextCommand =
                new RelayCommand(() =>
                {
                    if (configuration.InstallType == InstallType.Default)
                    {
                        navigationService.CurrentPage = container.Resolve<InstallationViewModel>();
                    }
                    else
                    {
                        navigationService.CurrentPage = container.Resolve<ConfigurationViewModel>();
                    }
                    
                }, () => LicenseAccepted);
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
