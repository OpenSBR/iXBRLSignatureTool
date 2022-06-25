using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Data;
using OpenSBR.Signature;

namespace SignXBRL
{
	[ValueConversion(typeof(SignatureType), typeof(string))]
	public class SignatureTypeValueConverter : IValueConverter
	{
		public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
		{
			switch ((SignatureType)value)
			{
				case SignatureType.Document:
					return "Document signature";
				case SignatureType.CounterSignature:
					return "Countersignature";
			}
			return "Generic signature";
		}

		public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
		{
			throw new NotImplementedException();
		}
	}
}
