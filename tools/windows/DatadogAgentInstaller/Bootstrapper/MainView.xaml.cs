using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using Microsoft.Tools.WindowsInstallerXml.Bootstrapper;

namespace Bootstrapper
{
    /// <summary>
    /// Interaction logic for MainView.xaml
    /// </summary>
    public partial class MainView : Window
    {
        readonly MainViewModel _viewModel;

        public MainView(BootstrapperApplication bootstrapper)
        {
            InitializeComponent();
            DataContext = _viewModel = new MainViewModel(bootstrapper);
        }

        void Install_Click(object sender, RoutedEventArgs e)
        {
            _viewModel.InstallExecute();
        }

        void Uninstall_Click(object sender, RoutedEventArgs e)
        {
            _viewModel.UninstallExecute();
        }

        void Exit_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
