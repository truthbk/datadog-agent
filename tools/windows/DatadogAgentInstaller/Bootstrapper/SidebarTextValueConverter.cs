using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace Bootstrapper
{
    public class SidebarTextValueConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value.GetType().Name == (string)parameter)
            {
                return new SolidColorBrush(Colors.White);
            }
            return new SolidColorBrush(Colors.LightGray);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
