using Microsoft.Tools.WindowsInstallerXml.Bootstrapper;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace Bootstrapper
{
    public class ManagedBA : BootstrapperApplication
    {
        /// <summary>
        /// Entry point that is called when the bootstrapper application is ready to run.
        /// </summary>
        protected override void Run()
        {
            Engine.Log(LogLevel.Verbose, "Running the TestBA.");
            MessageBox.Show("It works !");
            //new MainView(this).ShowDialog();
            Engine.Quit(0);
        }
    }
}
