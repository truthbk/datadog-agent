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
            new MainView(this).ShowDialog();
            Engine.Quit(0);
        }
    }
}
