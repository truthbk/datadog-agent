using System.Collections.Generic;
using System.Diagnostics;
using System.Windows;
using System.Windows.Documents;
using Bootstrapper;
using Microsoft.Tools.WindowsInstallerXml.Bootstrapper;

namespace Bootstrapper
{
    public class MainViewModel : BaseViewModel
{
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

        public MainViewModel(BootstrapperApplication bootstrapper)
        {
            Debugger.Launch();
            CurrentPage = new WelcomeViewModel(this);

            IsBusy = false;

            Bootstrapper = bootstrapper;
            Bootstrapper.Error += OnError;
            Bootstrapper.ApplyComplete += OnApplyComplete;
            Bootstrapper.DetectPackageComplete += OnDetectPackageComplete;
            Bootstrapper.PlanComplete += OnPlanComplete;

            Bootstrapper.Engine.Detect();
        }

        void OnError(object sender, ErrorEventArgs e)
        {
            MessageBox.Show(e.ErrorMessage);
        }

        bool installEnabled;

        public bool InstallEnabled
        {
            get => installEnabled;
            set
            {
                installEnabled = value;
                OnPropertyChanged();
            }
        }

        bool uninstallEnabled;

        public bool UninstallEnabled
        {
            get => uninstallEnabled;
            set
            {
                uninstallEnabled = value;
                OnPropertyChanged();
            }
        }

        bool isThinking;

        public bool IsBusy
        {
            get => isThinking;
            set
            {
                isThinking = value;
                OnPropertyChanged();
            }
        }

        public BootstrapperApplication Bootstrapper { get; set; }

        public void InstallExecute()
        {
            IsBusy = true;

            //Bootstrapper.Engine.StringVariables["UserInput"] = UserInput;
            Bootstrapper.Engine.Plan(LaunchAction.Install);
        }

        public void UninstallExecute()
        {
            IsBusy = true;
            Bootstrapper.Engine.Plan(LaunchAction.Uninstall);
        }

        public void ExitExecute()
        {
            //Dispatcher.BootstrapperDispatcher.InvokeShutdown();
        }

        /// <summary>
        /// Method that gets invoked when the Bootstrapper ApplyComplete event is fired.
        /// This is called after a bundle installation has completed. Make sure we updated the view.
        /// </summary>
        void OnApplyComplete(object sender, ApplyCompleteEventArgs e)
        {
            IsBusy = false;
            InstallEnabled = false;
            UninstallEnabled = false;
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
                    InstallEnabled = true;
                }
                else if (e.State == PackageState.Present)
                {
                    UninstallEnabled = true;
                }
            }
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
                Bootstrapper.Engine.Apply(System.IntPtr.Zero);
            }
        }
    }
}
