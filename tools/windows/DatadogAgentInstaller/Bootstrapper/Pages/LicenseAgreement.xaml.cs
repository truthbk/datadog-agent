using System;
using System.Collections.Generic;
using System.IO;
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
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace Bootstrapper.Pages
{
    public class RichTextBoxHelper : DependencyObject
    {
        public static string GetDocumentContent(DependencyObject obj)
        {
            return (string)obj.GetValue(DocumentContentProperty);
        }

        public static void SetDocumentContent(DependencyObject obj, string value)
        {
            obj.SetValue(DocumentContentProperty, value);
        }

        // Using a DependencyProperty as the backing store for DocumentContent.  This enables animation, styling, binding, etc...
        public static readonly DependencyProperty DocumentContentProperty =
            DependencyProperty.RegisterAttached("DocumentContent", typeof(string), typeof(RichTextBoxHelper),
                new FrameworkPropertyMetadata
                {
                    BindsTwoWayByDefault = false,
                    PropertyChangedCallback = (obj, e) =>
                    {
                        var richTextBox = (RichTextBox)obj;
                        if (richTextBox != null)
                        {
                            // Parse the XAML to a document (or use XamlReader.Parse())
                            var xaml = GetDocumentContent(richTextBox);
                            if (xaml != null)
                            {
                                using (var reader = new MemoryStream(Encoding.UTF8.GetBytes(xaml)))
                                {
                                    reader.Position = 0;
                                    richTextBox.SelectAll();
                                    richTextBox.Selection.Load(reader, DataFormats.Rtf);
                                }
                            }
                        }
                    }
                });
    }

    /// <summary>
    /// Interaction logic for LicenseAgreement.xaml
    /// </summary>
    public partial class LicenseAgreement : UserControl
    {
        public LicenseAgreement()
        {
            InitializeComponent();
        }
    }
}
