using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml.Patched;
using System.Text;
using System.Xml;

namespace OpenSBR.XAdES
{
	public enum SignatureType
	{
		XmlDSig,
		Xades111,
		Xades132,
		Xades141 = Xades132,
		Xades = Xades141
	}

	public class Xades
	{
		public static readonly string XadesNamespaceUrl = "http://uri.etsi.org/01903/v1.3.2#";
		public static readonly string Xades111ReferenceType = "http://uri.etsi.org/01903/v1.1.1#SignedProperties";
		public static readonly string XadesReferenceType = "http://uri.etsi.org/01903#SignedProperties";        // Changed in the 1.3.2 specification
		public static readonly string CounterSignatureRefernceType = "http://uri.etsi.org/01903#CountersignedSignature";

		public static string XadesSignedPropertiesId = "signed-properties";
		public static string XadesSignatureRootId = "signature-root";

		public delegate Stream UriResolverDelegate(string uri);

		private delegate bool CheckSignedInfoDelegate(SignedXml signedXml, AsymmetricAlgorithm key);
		private static CheckSignedInfoDelegate _checkSignedInfo;
		private static MethodInfo _calculateHashValue;

		/// <summary>
		/// Static constructor to add xmldsig-filter2 and apply nodelist fixes
		/// </summary>
		static Xades()
		{
			CryptoConfig.AddAlgorithm(typeof(XmlDsigFilterTransform), XmlDsigFilterTransform.AlgorithmURI);

			_checkSignedInfo = (CheckSignedInfoDelegate)typeof(SignedXml).GetMethod("CheckSignedInfo", BindingFlags.NonPublic | BindingFlags.Instance, null, new Type[] { typeof(AsymmetricAlgorithm) }, null).CreateDelegate(typeof(CheckSignedInfoDelegate));
			_calculateHashValue = typeof(Reference).GetMethod("CalculateHashValue", BindingFlags.NonPublic | BindingFlags.Instance);
		}

		/// <summary>
		/// Allows for manual initialization (forces invocation of static constructor)
		/// This would only be useful in case Transforms are parsed before a XadesSignature instance is created
		/// </summary>
		public static void Init()
		{ }


		private XmlDocument _document;
		private XmlElement _signatureParent;
		private SignedXml _signedXml;

		private XmlElement _signedProperties;
		private Dictionary<Reference, XadesReference> _referenceIndex;

		private Xades(XmlDocument document, XmlElement signatureParent)
		{
			_document = document;
			_signatureParent = signatureParent;

			SignatureProperties = new XadesSignatureProperties();
			References = new List<XadesReference>();

			// set defaults
			SignatureType = SignatureType.Xades;

			CanonicalizationMethod = SignedXml.XmlDsigExcC14NWithCommentsTransformUrl;
			DigestMethod = SignedXml.XmlDsigSHA256Url;
			SignatureMethod = SignedXml.XmlDsigRSASHA256Url;

			XadesTransformChain = new TransformChain();
			XadesTransformChain.Add(new XmlDsigExcC14NTransform());
			XadesDigestMethod = SignedXml.XmlDsigSHA256Url;
		}

		/// <summary>
		/// Create a signature document
		/// </summary>
		public static Xades Create(XmlDocument document = null, XmlElement signatureParent = null)
		{
			return new Xades(document, signatureParent);
		}

		private Xades(XmlElement element)
		{
			_document = element.OwnerDocument;
			_signedXml = new XadesSignedXml(_document);
			_signedXml.LoadXml(element);

			CanonicalizationMethod = _signedXml.SignedInfo.CanonicalizationMethod;
			SignatureMethod = _signedXml.SignedInfo.SignatureMethod;

			XmlNamespaceManager nsm = new XmlNamespaceManager(new NameTable());
			nsm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
			nsm.AddNamespace("xades", XadesNamespaceUrl);

			// find the xades reference
			_referenceIndex = new Dictionary<Reference, XadesReference>();
			References = new List<XadesReference>();
			foreach (Reference reference in _signedXml.SignedInfo.References)
			{
				if (reference.Type == Xades.XadesReferenceType && !string.IsNullOrEmpty(reference.Uri) && reference.Uri[0] == '#')
				{
					XmlElement signedProperties = element.SelectSingleNode($"//xades:SignedProperties[@Id='{reference.Uri.Substring(1)}']", nsm) as XmlElement;
					if (signedProperties != null)
					{
						_signedProperties = signedProperties;
						_referenceIndex[reference] = null;
						continue;
					}
				}
				// external reference
				XadesReference xadesReference = new XadesReference(reference);
				_referenceIndex[reference] = xadesReference;
				References.Add(xadesReference);
			}
			if (_signedProperties == null)
				return;

			// parse signature policy
			SignatureProperties = new XadesSignatureProperties(_signedProperties, nsm);

			// create xades files
			foreach (XadesReference item in References)
				item.ParseProperties(_signedProperties, nsm);
		}

		/// <summary>
		/// Load signature from element
		/// </summary>
		/// <param name="element"></param>
		public static Xades Load(XmlElement signatureElement)
		{
			return new Xades(signatureElement);
		}

		public static Xades Load(XmlDocument signatureDocument)
		{
			return Load(signatureDocument.DocumentElement);
		}

		public static Xades Load(Stream signatureStream)
		{
			XmlDocument document = new XmlDocument();
			document.PreserveWhitespace = true;
			document.Load(signatureStream);
			return Load(document);
		}

		/// <summary>
		/// Get or set the canonicalization method; use a value from System.Security.Cryptography.Xml.SignedXml
		/// </summary>
		public string CanonicalizationMethod { get; set; }

		public string DigestMethod { get; set; }

		/// <summary>
		/// Get or set the signature method; use a value from System.Security.Cryptography.Xml.SignedXml
		/// </summary>
		public string SignatureMethod { get; set; }

		public TransformChain XadesTransformChain { get; set; }

		public string XadesDigestMethod { get; set; }

		/// <summary>
		/// Signature properties (Signature policy)
		/// </summary>
		public XadesSignatureProperties SignatureProperties { get; }

		//public List<XmlElement> UnsignedSignatureProperties { get; }

		/// <summary>
		/// List of references to sign
		/// </summary>
		public List<XadesReference> References { get; }

		public UriResolverDelegate UriResolver { get; set; }

		private HashSet<string> _documentIds;
		private static Random _rnd = new Random();

		public SignatureType SignatureType { get; set; }

		/// <summary>
		/// Create Xades signature of the included files
		/// </summary>
		/// <param name="certificate"></param>
		/// <param name="resolver"></param>
		/// <returns></returns>
		public XmlElement Sign(X509Certificate2 certificate)
		{
			XmlDocument document = _document ?? new XmlDocument();

			_documentIds = new HashSet<string>(document.SelectNodes("//@id | //@Id").OfType<XmlAttribute>().Select(x => x.Value));
			// reserve or generate item ids
			CheckItemIds();

			//SignedXml signedXml = _signatureParent != null ? new SignedXml(_signatureParent) : new SignedXml(document);
			XadesSignedXml signedXml = _signatureParent != null ? new XadesSignedXml(_signatureParent) : new XadesSignedXml(document);
			signedXml.SignedInfo.CanonicalizationMethod = CanonicalizationMethod;
			signedXml.SignedInfo.SignatureMethod = SignatureMethod;

			// if Xades, add object, qualifyingproperties and signedproperties
			if (SignatureType != SignatureType.XmlDSig)
				CreateXadesQualifyingProperties(signedXml, document, certificate);

			// add reference for each file
			foreach (XadesReference item in References)
			{
				if (item.Fragment != null)
					signedXml.AddXadesObject(new DataObject(item.Id, null, null, (XmlElement)document.ImportNode(item.Fragment, true)));
				signedXml.AddReference(item.GetReference(UriResolver));
			}

			// set key
			KeyInfo keyInfo = new KeyInfo();
			keyInfo.AddClause(new KeyInfoX509Data(certificate, X509IncludeOption.WholeChain));
			signedXml.SigningKey = certificate.GetRSAPrivateKey();
			signedXml.KeyInfo = keyInfo;

			// calculate signature
			signedXml.ComputeSignature();
			XmlElement root = signedXml.GetXml();

			return root;
		}

		private void CheckItemIds()
		{
			foreach (XadesReference item in References)
			{
				if (item.Id == null || _documentIds.Contains(item.Id))
					item.Id = CreateId("itemref");
				else
					_documentIds.Add(item.Id);
			}
		}

		private string CreateId(string baseId)
		{
			for (; ; )
			{
				string id = $"{baseId}-{_rnd.Next():x8}";
				if (!_documentIds.Contains(id))
				{
					_documentIds.Add(id);
					return id;
				}
			}
		}

		/// <summary>
		/// Create Xades <QualifyingProperties> from the <SignatureProperties> and <DataObjectProperties> elements
		/// </summary>
		/// <param name="signedXml"></param>
		/// <param name="document"></param>
		/// <param name="certificate"></param>
		private void CreateXadesQualifyingProperties(XadesSignedXml signedXml, XmlDocument document, X509Certificate2 certificate)
		{
			string signatureRootId = CreateId(XadesSignatureRootId);
			string signedPropertiesId = CreateId(XadesSignedPropertiesId);

			// build xades XML
			XmlElement qualifyingProperties = document.CreateElement("QualifyingProperties", XadesNamespaceUrl);
			qualifyingProperties.SetAttribute("Target", $"#{signatureRootId}");
			XmlElement signedProperties = qualifyingProperties.CreateChild("SignedProperties", XadesNamespaceUrl);
			signedProperties.SetAttribute("Id", signedPropertiesId);

			XmlElement signatureProperties = SignatureProperties.CreateXadesSignatureProperties(document, certificate, SignatureType);
			signedProperties.AppendChild(signatureProperties);
			XmlElement dataObjectProperties = CreateXadesDataObjectProperties(document);
			if (dataObjectProperties.ChildNodes.Count > 0)
				signedProperties.AppendChild(dataObjectProperties);

			// add reference to xades XML
			signedXml.AddXadesObject(new DataObject(null, null, null, qualifyingProperties));
			Reference signedPropertiesReference = new Reference($"#{signedPropertiesId}") { TransformChain = XadesTransformChain, DigestMethod = XadesDigestMethod, Type = XadesReferenceType };
			signedXml.AddReference(signedPropertiesReference);

			signedXml.Signature.Id = signatureRootId;
		}

		/// <summary>
		/// Create Xades <DataObjectProperties>
		/// </summary>
		/// <param name="document"></param>
		/// <returns></returns>
		private XmlElement CreateXadesDataObjectProperties(XmlDocument document)
		{
			XmlElement dataObjectProperties = document.CreateElement("SignedDataObjectProperties", XadesNamespaceUrl);
			foreach (XadesReference item in References)
				item.AddObjectFormat(dataObjectProperties);
			// group by identical commmitment type
			Dictionary<string, XmlElement> commitmentTypeIndex = new Dictionary<string, XmlElement>();
			foreach (XadesReference item in References.Where(x => x.CommitmentTypeId != null))
			{
				string id = item.CommitmentTypeId.ToString();
				if (item.CommitmentTypeQualifiers != null)
					id = $"{id};{String.Join(";", item.CommitmentTypeQualifiers.Select(x => x.OuterXml))}";
				if (commitmentTypeIndex.TryGetValue(id, out XmlElement commitmentTypeIndication))
					item.AddObjectReference(commitmentTypeIndication);
				else
					commitmentTypeIndex[id] = item.AddCommitmentTypeIndication(dataObjectProperties);
			}
			return dataObjectProperties;
		}

		/// <summary>
		/// Check Xades signature; SignedXml.CheckSignature would do all the work, but does not provide detailed feedback
		/// </summary>
		/// <param name="certificate"></param>
		/// <param name="resolver"></param>
		/// <returns></returns>
		public bool CheckSignature(out X509Certificate2 certificate, UriResolverDelegate resolver = null)
		{
			certificate = null;

			if (_signedXml == null)
				return false;

			// find appropriate public key and verify signature
			bool ValidSignedInfo = false;
			foreach (KeyValuePair<AsymmetricAlgorithm, X509Certificate2> algInfo in GetPublicKeys(_signedXml.KeyInfo))
			{
				if (_checkSignedInfo(_signedXml, algInfo.Key))
				{
					ValidSignedInfo = true;
					certificate = algInfo.Value;
					break;
				}
			}

			// verify reference hashes
			bool validReferences = true;
			bool ValidSignedProperties = false;
			foreach (Reference reference in _signedXml.SignedInfo.References)
			{
				byte[] digest = CalculateHash(reference, resolver);
				bool validReference = reference.DigestValue.SequenceEqual(digest);
				// store result
				XadesReference xadesReference = _referenceIndex[reference];
				if (xadesReference == null)
					ValidSignedProperties = validReference;
				else
					xadesReference.IsValid = validReference;
				validReferences = validReference && validReferences;
			}

			return ValidSignedInfo && validReferences && ValidSignedProperties;
		}

		private byte[] CalculateHash(Reference reference, UriResolverDelegate resolver)
		{
			if (reference.Uri == null || reference.Uri.Length == 0 || reference.Uri[0] == '#')
				return (byte[])_calculateHashValue.Invoke(reference, new object[] { _document, null });

			try
			{
				Stream stream;
				if (resolver != null)
					stream = resolver(Uri.UnescapeDataString(reference.Uri));
				else
					using (WebClient wc = new WebClient())
						stream = wc.OpenRead(reference.Uri);
				return XadesUtils.CalculateHash(stream, reference.TransformChain, reference.DigestMethod);
			}
			catch (Exception)
			{
				return new byte[0];
			}
		}

		/// <summary>
		/// Enumerate all public keys (with their certificate if available) in keyInfo
		/// </summary>
		/// <param name="keyInfo"></param>
		/// <returns></returns>
		private IEnumerable<KeyValuePair<AsymmetricAlgorithm, X509Certificate2>> GetPublicKeys(KeyInfo keyInfo)
		{
			System.Collections.IEnumerator enumerator = keyInfo.GetEnumerator();
			while (enumerator.MoveNext())
			{
				switch (enumerator.Current)
				{
					case KeyInfoX509Data keyInfoX509Data:
						foreach (X509Certificate2 certificate in keyInfoX509Data.Certificates)
						{
							AsymmetricAlgorithm asyncAlg = certificate.GetRSAPublicKey() ?? (AsymmetricAlgorithm)certificate.GetECDsaPublicKey();
							if (asyncAlg != null)
								yield return new KeyValuePair<AsymmetricAlgorithm, X509Certificate2>(asyncAlg, certificate);
						}
						break;
					case RSAKeyValue rsaKeyValue:
						yield return new KeyValuePair<AsymmetricAlgorithm, X509Certificate2>(rsaKeyValue.Key, null);
						break;
					case DSAKeyValue dsaKeyValue:
						yield return new KeyValuePair<AsymmetricAlgorithm, X509Certificate2>(dsaKeyValue.Key, null);
						break;
				}
			}
		}
	}
}
