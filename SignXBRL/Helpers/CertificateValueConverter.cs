using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Data;

namespace SignXBRL
{
	[ValueConversion(typeof(X509Certificate2), typeof(string))]
	public class CertificateValueConverter : IValueConverter
	{
		public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
		{
			System.Security.Cryptography.X509Certificates.X509Certificate2 cert = value as System.Security.Cryptography.X509Certificates.X509Certificate2;
			if ("ca".Equals(parameter))
				return cert?.IssuerInfo();
			return cert?.SubjectInfo();
		}

		public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
		{
			throw new NotImplementedException();
		}
	}
}
