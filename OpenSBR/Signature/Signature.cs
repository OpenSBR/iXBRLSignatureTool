using OpenSBR.XAdES;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml.Patched;
using System.Xml;

namespace OpenSBR.Signature
{
	public enum SignatureType
	{
		Document,
		CounterSignature,
		Generic
	}

	/// <summary>
	/// A single signature within a signature document
	/// </summary>
	public class Signature
	{
		public bool IsValid { get; }
		public SignatureType Type { get; }

		public List<SignedItem> Items { get; }

		public DateTime? SignatureDate { get; }
		public SignaturePolicy SignaturePolicy { get; set; }
		public X509Certificate2 Certificate { get; }
		public bool CertificateIsValid { get; }
		public string CertificateError { get; }
		public X509Certificate2 CACertificate { get; }

		public List<Signature> Signatures { get; }

		public XmlElement XmlElement { get; private set; }
		private Xades _xades;

		internal Signature(XmlElement signatureElement, ILookup<XmlElement, XmlElement> childIndex)
		{
			// store element for countersigning
			XmlElement = signatureElement;
			// parse signature
			_xades = Xades.Load(signatureElement);
			// check signature; resolve external references relative to main document
			string baseUri = signatureElement.OwnerDocument?.BaseURI;
			IsValid = _xades.CheckSignature(out X509Certificate2 certificate, u =>
			{
				Uri uri = baseUri == null ? new Uri(u) : new Uri(new Uri(baseUri), u);
				return File.OpenRead(uri.LocalPath);
			});
			// store certificate
			Certificate = certificate;
			if (certificate != null)
			{
				X509Chain chain = new X509Chain();
				chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
				//chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
				CertificateIsValid = chain.Build(certificate);
				CertificateError = (CertificateIsValid == false) ? chain.ChainStatus?.First().StatusInformation.Trim() : null;
				CACertificate = chain.ChainElements.OfType<X509ChainElement>().LastOrDefault(x => x.Certificate.Extensions.OfType<X509BasicConstraintsExtension>().Any(y => y.CertificateAuthority))?.Certificate;
			}

			XadesSignatureProperties signatureProperties = _xades.SignatureProperties;
			if (signatureProperties != null)
			{
				// store date
				SignatureDate = _xades.SignatureProperties.SigningTime;

				// read signature policy
				if (signatureProperties.PolicyImplied)
					SignaturePolicy = new SignaturePolicy();
				else if (signatureProperties.PolicyId != null)
					SignaturePolicy = new SignaturePolicy(signatureProperties.PolicyId);
			}

			// store signed item references
			Items = _xades.References.Select(x => new SignedItem(signatureElement, x, SignaturePolicy)).ToList();
			// determine type of signature
			Type = Items.Any(x => x.Type == SignedItemType.Document) ? SignatureType.Document : Items.Any(x => x.Type == SignedItemType.Signature) ? SignatureType.CounterSignature : SignatureType.Generic;

			// parse child signatures
			Signatures = childIndex[signatureElement].Select(x => new Signature(x, childIndex)).ToList();
		}

		public bool Countersign(X509Certificate2 cert, List<SignedItem> items, SignaturePolicy policy)
		{
			XmlDocument xmlDocument = XmlElement.OwnerDocument;

			// find or add id to signature value
			XmlElement signatureValue = XmlElement["SignatureValue", SignedXml.XmlDsigNamespaceUrl];
			if (signatureValue == null)
				return false;
			string id = (signatureValue.Attributes["Id"] ?? signatureValue.Attributes["id"])?.Value;
			if (id == null)
			{
				HashSet<string> ids = new HashSet<string>(xmlDocument.SelectNodes("//@id | //@Id").OfType<XmlAttribute>().Select(x => x.Value));
				Random rnd = new Random();
				for (; ; )
				{
					id = $"signature-value-{rnd.Next():x8}";
					if (!ids.Contains(id))
						break;
				}
				signatureValue.SetAttribute("Id", id);
			}

			// find or add unsigned properties
			XmlElement qualifyingProperties = XmlElement.ChildNodes.OfType<XmlElement>().Where(x => x.LocalName == "Object" && x.NamespaceURI == SignedXml.XmlDsigNamespaceUrl).Select(x => x["QualifyingProperties", Xades.XadesNamespaceUrl]).SingleOrDefault(x => x != null);
			if (qualifyingProperties == null)
				return false;
			XmlElement unsignedSignatureProperties = qualifyingProperties.GetOrCreate("UnsignedProperties", Xades.XadesNamespaceUrl).GetOrCreate("UnsignedSignatureProperties", Xades.XadesNamespaceUrl);
			XmlElement signatureLocation = xmlDocument.CreateElement("CounterSignature", Xades.XadesNamespaceUrl);
			unsignedSignatureProperties.AppendChild(signatureLocation);

			// create signature
			Xades xades = Xades.Create(xmlDocument, signatureLocation);
			xades.SignatureProperties.SigningTime = DateTime.UtcNow;
			// add policy
			if (policy != null)
			{
				xades.SignatureProperties.PolicyId = new ObjectIdentifier() { Identifier = policy.Identifier, Description = policy.Description };
				xades.SignatureProperties.PolicyURIs = new List<string>() { policy.URI };
				// todo: determine transforms, calculate digest
			}
			// add countersignature reference
			XadesReference reference = new XadesReference($"#{id}", TransformSet.Signature.TransformChain) { Type = Xades.CounterSignatureRefernceType };
			SignedItem signatureItem = items.Single(x => x.Type == SignedItemType.Signature);
			if (policy != null && signatureItem.CommitmentType != null)
				reference.CommitmentTypeId = new ObjectIdentifier() { Identifier = signatureItem.CommitmentType.Identifier, Description = signatureItem.CommitmentType.Description };
			xades.References.Add(reference);
			// add other references
			foreach (SignedItem item in items.Where(x => x.Type != SignedItemType.Signature))
			{
				reference = new XadesReference(item.Uri, item.Transform.TransformChain);
				if (policy != null && item.CommitmentType != null)
					reference.CommitmentTypeId = new ObjectIdentifier() { Identifier = signatureItem.CommitmentType.Identifier, Description = signatureItem.CommitmentType.Description };
				xades.References.Add(reference);
			}
			// sign
			string baseUri = xmlDocument.BaseURI;
			xades.UriResolver = u =>
			{
				Uri uri = baseUri == null ? new Uri(u) : new Uri(new Uri(baseUri), u);
				return File.OpenRead(uri.LocalPath);
			};
			XmlElement result = xades.Sign(cert);
			signatureLocation.AppendChild(result);
			return true;
		}
	}
}
