using OpenSBR.Signature;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using System.Xml;

namespace SignXBRL
{
	/// <summary>
	/// Interaction logic for MainWindow.xaml
	/// </summary>
	public partial class MainWindow : Window, INotifyPropertyChanged
	{
		public MainWindow()
		{
			InitializeComponent();

			DataContext = this;
		}

		private string _filename;

		public string TitleFile { get => _filename != null ? $"GLEIF iXBRL Signature Tool - {Path.GetFileName(_filename)}" : null; }
		public SignatureDocument Document { get; set; }
		public Signature SelectedSignature { get; set; }
		public bool SignEnable { get => Document != null; }
		public bool CountersignEnable { get => SelectedSignature != null; }

		// drop handler
		private void Window_Drop(object sender, DragEventArgs e)
		{
			string file = e.GetFiles().SingleOrDefault();
			if (file == null)
				return;

			Load(file);
			e.Handled = true;
		}

		public async void Load(string file)
		{
			try
			{
				Cursor = Cursors.Wait;
				_filename = file;
				NotifyChange("TitleFile");
				Document = await Task.Run(() => SignatureDocument.Load(file));
				NotifyChange("Document");
				NotifyChange("SignEnable");
				NotifyChange("CountersignEnable");
				Cursor = null;
			}
			catch (XmlException)
			{
				_filename = null;
				NotifyChange("TitleFile");
				MessageBox.Show("The specified file is not a properly formatted XML (or XHTML) file");
			}
		}

		public void Save()
		{
			string signed = System.Text.RegularExpressions.Regex.Replace(_filename, @"(?:(\.signed)(\d*))?(\.[^.]+)$", m =>
			{
				if (!string.IsNullOrEmpty(m.Groups[2].Value))
					return $"{m.Groups[1].Value}{int.Parse(m.Groups[2].Value) + 1}{m.Groups[3].Value}";
				if (!string.IsNullOrEmpty(m.Groups[1].Value))
					return $"{m.Groups[1].Value}2{m.Groups[3].Value}";
				return $".signed{m.Groups[3].Value}";
			});
			if (File.Exists(signed))
				File.Delete(signed);
			Document.XmlDocument.Save(signed);
			_filename = signed;
		}

		private void TreeView_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
		{
			SelectedSignature = e.NewValue as Signature;
			NotifyChange("SelectedSignature");
			NotifyChange("CountersignEnable");
		}

		private void Sign_Click(object sender, RoutedEventArgs e)
		{
			SignatureDialog signatureDialog = new SignatureDialog(this, Document, null);

			if (signatureDialog.ShowDialog() == true)
			{
				Save();
				Load(_filename);
			}
		}

		private void Countersign_Click(object sender, RoutedEventArgs e)
		{
			SignatureDialog signatureDialog = new SignatureDialog(this, Document, SelectedSignature);

			if (signatureDialog.ShowDialog() == true)
			{
				Save();
				Load(_filename);
			}
		}

		#region INotifyPropertyChanged

		public event PropertyChangedEventHandler PropertyChanged;
		protected void NotifyChange([CallerMemberName] string property = null)
		{
			PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(property));
		}
		#endregion
	}

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
