using System.Diagnostics;
using Microsoft.MinIoC;
using Microsoft.Tools.WindowsInstallerXml.Bootstrapper;

namespace Bootstrapper
{
    public class MainViewModel : BaseViewModel, INavigationService
    {
        private readonly Container _container;
        private BaseViewModel _currentPage;

        public BaseViewModel CurrentPage
        {
            get => _currentPage;
            set
            {
                _currentPage = value;
                OnPropertyChanged();
            }
        }

        public MainViewModel(BootstrapperApplication bootstrapper, Container container)
        {
            _container = container;
            Debugger.Launch();

            //IsBusy = false;

            bootstrapper.DetectPackageComplete += OnDetectPackageComplete;
            bootstrapper.Engine.Detect();
        }

        /// <summary>
        /// Method that gets invoked when the Bootstrapper DetectPackageComplete event is fired.
        /// Checks the PackageId and sets the installation scenario. The PackageId is the ID
        /// specified in one of the package elements (msipackage, exepackage, msppackage,
        /// msupackage) in the WiX bundle.
        /// </summary>
        void OnDetectPackageComplete(object sender, DetectPackageCompleteEventArgs e)
        {
            if (e.PackageId == "DatadogAgent")
            {
                if (e.State == PackageState.Absent)
                {
                    //InstallEnabled = true;
                    CurrentPage = _container.Resolve<WelcomeViewModel>();
                }
                else if (e.State == PackageState.Present)
                {
                    //UninstallEnabled = true;
                }
            }
        }
    }
}
