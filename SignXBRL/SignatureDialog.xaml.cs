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

		enum DocumentType { any, ubl, ixbrl }

		// create signature
		private void Sign_Click(object sender, RoutedEventArgs e)
		{
			DocumentType documentType = DocumentType.any;

			// select certificate
			X509Certificate2 cert = SelectedCertificate;
			if (cert == null)
			{
				X509Certificate2Collection certs = X509Certificate2UI.SelectFromCollection(Utils.GetCertificates(), "Select a certificate", "Choose your certificate to sign documents and provide proof of integrity", X509SelectionFlag.SingleSelection);
				if (certs.Count < 1)
					return;
				cert = certs[0];
			}
			if (cert == null)
				return;

			Cursor = Cursors.Wait;

			XmlDocument xmlDocument = _document.XmlDocument;
			bool result = false;
			if (_parentSignature == null)
			{
				// find location for signature
				XmlElement signatureLocation = null;
				if (_document.Signatures.Any())
					signatureLocation = (XmlElement)_document.Signatures.First().XmlElement.ParentNode;
				else if (xmlDocument.DocumentElement.LocalName == "html" && xmlDocument.DocumentElement.NamespaceURI == "http://www.w3.org/1999/xhtml")
				{
					documentType = DocumentType.ixbrl;
					// find resources section
					XmlNamespaceManager nsm = new XmlNamespaceManager(new NameTable());
					nsm.AddNamespace("xhtml", "http://www.w3.org/1999/xhtml");
					nsm.AddNamespace("ix", "http://www.xbrl.org/2013/inlineXBRL");
					XmlElement resources = (XmlElement)xmlDocument.SelectSingleNode("/xhtml:html//ix:header/ix:resources", nsm);
					if (resources != null)
					{
						// create unique id for context
						HashSet<string> ids = xmlDocument.SelectNodes("//@id | //@Id").OfType<XmlAttribute>().Select(x => x.Value).ToHashSet();
						string contextId;
						Random rnd = new Random();
						for (contextId = "signature"; ids.Contains(contextId); contextId = $"signature-{rnd.Next():x8}") ;
						// create context
						XmlElement context = resources.CreateChild("context", "http://www.xbrl.org/2003/instance");
						context.SetAttribute("id", contextId);
						XmlElement entity = context.CreateChild("entity", "http://www.xbrl.org/2003/instance");
						XmlElement identifier = entity.CreateChild("identifier", "http://www.xbrl.org/2003/instance");
						identifier.SetAttribute("scheme", System.Security.Cryptography.Xml.SignedXml.XmlDsigNamespaceUrl);
						identifier.InnerText = "Signature";
						signatureLocation = entity.CreateChild("segment", "http://www.xbrl.org/2003/instance");
						XmlElement period = context.CreateChild("period", "http://www.xbrl.org/2003/instance");
						XmlElement forever = period.CreateChild("forever", "http://www.xbrl.org/2003/instance");
					}
					else
					{
						// no xbrl resources; treat as regular xhtml
						XmlElement body = (XmlElement)xmlDocument.SelectSingleNode("/xhtml:html/xhtml:body", nsm);
						signatureLocation = body.CreateChild("div", "http://www.w3.org/1999/xhtml");
						signatureLocation.SetAttribute("style", "display: none");
					}
				}
				else if (xmlDocument.DocumentElement.LocalName == "Invoice" && xmlDocument.DocumentElement.NamespaceURI == "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2")
				{
					documentType = DocumentType.ubl;
					// find resources section
					XmlNamespaceManager nsm = new XmlNamespaceManager(new NameTable());
					nsm.AddNamespace("ubl", "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2");
					nsm.AddNamespace("cbc", "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2");
					nsm.AddNamespace("cac", "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2");
					nsm.AddNamespace("ext", "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2");
					nsm.AddNamespace("sig", "urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2");
					nsm.AddNamespace("sac", "urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2");
					nsm.AddNamespace("sbc", "urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2");
					nsm.AddNamespace("sbc", "urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2");

					XmlElement body = xmlDocument.DocumentElement;

					XmlElement sibling = body.SelectSingleNode("cac:AccountingSupplierParty", nsm) as XmlElement;
					if (sibling != null)
					{
						XmlElement ublSignature = body.OwnerDocument.CreateElement("cac", "Signature", "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2");
						body.InsertBefore(ublSignature, sibling);

						//XmlElement ublSignature = body.CreateChild("Signature", "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2");
						ublSignature.CreateChild("ID", "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2", "urn:oasis:names:specification:ubl:signature:Invoice");
						ublSignature.CreateChild("ValidationDate", "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2", XmlConvert.ToString(DateTime.UtcNow, "yyyy-MM-ddZ"));
						ublSignature.CreateChild("ValidationTime", "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2", XmlConvert.ToString(DateTime.UtcNow, "HH:mm:ssZ"));
						ublSignature.CreateChild("SignatureMethod", "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2", "urn:oasis:names:specification:ubl:dsig:enveloped");

						string lei = cert.GLEIFLEI();
						if (lei != null)
						{
							XmlElement party = ublSignature.CreateChild("SignatoryParty", "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2");
							XmlElement partyIdentification = party.CreateChild("PartyIdentification", "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2");
							XmlElement partyIdentificationId = partyIdentification.CreateChild("ID", "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2");

							partyIdentificationId.SetAttribute("schemeID", "LEI");
							partyIdentificationId.InnerText = lei;
						}
					}

					XmlElement extensions = body.FindOrCreateChild("UBLExtensions", "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2", nsm, true);
					XmlElement extension = extensions.CreateChild("UBLExtension", "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2");
					XmlElement extensionContent = extension.CreateChild("ExtensionContent", "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2");
					XmlElement documentSignatures = extensionContent.CreateChild("UBLDocumentSignatures", "urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2");
					signatureLocation = documentSignatures.CreateChild("SignatureInformation", "urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2");

					//signatureLocation = extensionContent;

					//XmlElement signatureExtension = null;
					//if (extensions == null)
					//{
					//	extensions = body.CreateChild("UBLExtensions", "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2");
					//	signatureExtension = extensions.CreateChild("UBLExtension", "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2");
					//}
					//else
					//{

					//}


					//{
					//	// no xbrl resources; treat as regular xhtml
					//	//XmlElement body = (XmlElement)xmlDocument.SelectSingleNode("/ubl:Invoice", nsm);
					//	//if (body != null)
					//	//{
					//	//	signatureLocation = body.CreateChild("UBLExtensions", "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2");
					//	//	//signatureLocation.SetAttribute("style", "display: none");
					//	//}
					//}
				}
				else
					signatureLocation = xmlDocument.DocumentElement;

				if (signatureLocation != null)
				{
					switch (documentType)
					{
						case DocumentType.ubl:
							result = _document.SignUbl(signatureLocation, cert, Items.ToList(), SelectedPolicy);
							break;
						case DocumentType.any:
						case DocumentType.ixbrl:
						default:
							result = _document.Sign(signatureLocation, cert, Items.ToList(), SelectedPolicy);
							break;
					}
				}
				else
				{
					MessageBox.Show(this, "Unable to find the required document location", "Error signing", MessageBoxButton.OK, MessageBoxImage.Error);
				}
			}
			else
			{
				result = _parentSignature.Countersign(cert, Items.ToList(), SelectedPolicy);
			}

			Cursor = null;

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
