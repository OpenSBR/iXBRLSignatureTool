using Microsoft.Win32;
using OpenSBR.Signature;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Xml;

namespace SignXBRL
{
	/// <summary>
	/// Interaction logic for SignatureDialog.xaml
	/// </summary>
	public partial class SignatureDialog : Window, INotifyPropertyChanged
	{
		public SignatureDialog(Window owner, SignatureDocument document, Signature parentSignature)
		{
			InitializeComponent();

			Owner = owner;

			Items = new ObservableCollection<SignedItem>();
			Items.Add(new SignedItem() { Type = parentSignature == null ? SignedItemType.Document : SignedItemType.Signature });

			CertificateList = new ObservableCollection<X509Certificate2>(Utils.GetCertificates().OfType<X509Certificate2>());

			SelectedPolicy = Policies?.FirstOrDefault();
			SelectedCertificate = CertificateList.FirstOrDefault();

			_document = document;
			_parentSignature = parentSignature;
			_lastDirectory = Path.GetDirectoryName(document.BaseUri);

			DataContext = this;
		}

		private SignatureDocument _document;
		private Signature _parentSignature;
		private string _lastDirectory;

		public ObservableCollection<SignedItem> Items { get; private set; }

		public ObservableCollection<SignaturePolicy> Policies { get; private set; }
		public SignaturePolicy SelectedPolicy { get; set; }

		public ObservableCollection<X509Certificate2> CertificateList { get; private set; }
		public X509Certificate2 SelectedCertificate { get; set; }

		private void AddFiles_Click(object sender, RoutedEventArgs e)
		{
			OpenFileDialog ofd = new OpenFileDialog();
			ofd.InitialDirectory = _lastDirectory;
			ofd.Multiselect = true;
			ofd.Filter = "XBRL/XML files|*.xbrl;*.xml|XML schemas (XSD)|*.xsd|All files|*.*";
			if (ofd.ShowDialog() != true)
				return;
			_lastDirectory = Path.GetDirectoryName(ofd.FileName);
			AddFileList(ofd.FileNames);
		}

		// drop handler
		private void Window_Drop(object sender, DragEventArgs e)
		{
			AddFileList(e.GetFiles());
			e.Handled = true;
		}

		private void AddFileList(IEnumerable<string> files)
		{
			foreach (string file in files)
			{
				Uri uri = new Uri(file, UriKind.RelativeOrAbsolute);
				if (uri.IsFile && File.GetAttributes(uri.LocalPath).HasFlag(FileAttributes.Directory))
				{
					// if uri points to a directory, add the contents instead (notes: does not recurse into subdirectories)
					AddFileList(Directory.GetFiles(uri.LocalPath));
				}
				else
					AddFile(uri);
			}
		}

		// add file, remove duplicate names, replace signature
		private void AddFile(Uri uri)
		{
			string relativeUri = new Uri(_document.BaseUri).MakeRelativeUri(uri).ToString();

			for (int i = Items.Count - 1; i >= 0; i--)
				if (Items[i].Uri == relativeUri)
					Items.RemoveAt(i);

			bool isXml = false;
			try
			{
				using (Stream stream = File.OpenRead(uri.LocalPath))
				using (XmlReader reader = XmlReader.Create(stream))
				{
					if (reader.Read())
						isXml = true;
				}
			}
			catch (Exception)
			{ }

			Items.Add(new SignedItem() { Uri = relativeUri, Type = SignedItemType.File, Transform = isXml ? TransformSet.XMLFile : TransformSet.File });
		}

		private void RemoveItem_Click(object sender, RoutedEventArgs e)
		{
			SignedItem item = (sender as Button)?.DataContext as SignedItem;
			Items.Remove(item);
			NotifyChange("SignEnable");
		}

		// re-evaluate sign state after policy selection changed
		private void CommitmentType_SelectionChanged(object sender, SelectionChangedEventArgs e)
		{
			NotifyChange("SignEnable");
		}

		// create signature
		private void Sign_Click(object sender, RoutedEventArgs e)
		{
			// select certificate
			X509Certificate2 cert = SelectedCertificate;
			if (cert == null)
			{
				X509Certificate2Collection certs = X509Certificate2UI.SelectFromCollection(Utils.GetCertificates(), "Select a certificate", "Choose your certifcate to sign documents and provide proof of integrity", X509SelectionFlag.SingleSelection);
				if (certs.Count < 1)
					return;
				cert = certs[0];
			}
			if (cert == null)
				return;

			Cursor lastCursor = Cursor;
			Cursor = Cursors.Wait;

			XmlDocument xmlDocument = _document.XmlDocument;
			bool result;
			if (_parentSignature == null)
			{
				// find location for signature
				XmlElement signatureLocation;
				if (_document.Signatures.Any())
					signatureLocation = (XmlElement)_document.Signatures.First().XmlElement.ParentNode;
				else if (xmlDocument.DocumentElement.LocalName == "html" && xmlDocument.DocumentElement.NamespaceURI == "http://www.w3.org/1999/xhtml")
				{
					XmlNamespaceManager nsm = new XmlNamespaceManager(new NameTable());
					nsm.AddNamespace("xhtml", "http://www.w3.org/1999/xhtml");
					XmlElement body = (XmlElement)xmlDocument.SelectSingleNode("/xhtml:html/xhtml:body", nsm);
					signatureLocation = xmlDocument.CreateElement("div", "http://www.w3.org/1999/xhtml");
					signatureLocation.SetAttribute("style", "display: none");
					body.AppendChild(signatureLocation);
				}
				else
					signatureLocation = xmlDocument.DocumentElement;

				result = _document.Sign(signatureLocation, cert, Items.ToList(), SelectedPolicy);
			}
			else
			{
				result = _parentSignature.Countersign(cert, Items.ToList(), SelectedPolicy);
			}

			Cursor = lastCursor;

			DialogResult = result;
			Close();
		}

		#region INotifyPropertyChanged

		public event PropertyChangedEventHandler PropertyChanged;
		protected void NotifyChange([CallerMemberName] string property = null)
		{
			PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(property));
		}
		#endregion
	}
}
