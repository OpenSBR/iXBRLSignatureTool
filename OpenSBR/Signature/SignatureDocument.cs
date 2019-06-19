using OpenSBR.XAdES;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace OpenSBR.Signature
{
	/// <summary>
	/// Document with signatures or to be signed
	/// </summary>
	public class SignatureDocument
	{
		public List<Signature> Signatures { get; private set; }
		public string BaseUri { get => XmlDocument.BaseURI; }

		public XmlDocument XmlDocument { get; private set; }

		public static SignatureDocument Load(string file)
		{
			XmlDocument document = new XmlDocument();
			document.PreserveWhitespace = true;
			document.Load(file);
			return Load(document);
		}

		public static SignatureDocument Load(XmlDocument document)
		{
			IEnumerable<XmlElement> signatureNodes = document.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl).OfType<XmlElement>();
			ILookup<XmlElement, XmlElement> childIndex = signatureNodes.ToLookup(x => GetParentElement(x, "Signature", SignedXml.XmlDsigNamespaceUrl));

			return new SignatureDocument()
			{
				XmlDocument = document,
				Signatures = childIndex[null].Select(x => new Signature(x, childIndex)).ToList()
			};
		}

		private static XmlElement GetParentElement(XmlElement element, string localName, string namespaceURI)
		{
			for (element = element.ParentNode as XmlElement; element != null; element = element.ParentNode as XmlElement)
			{
				if (element.LocalName == localName && element.NamespaceURI == namespaceURI)
					return element;
			}
			return null;
		}

		public bool Sign(XmlElement signatureLocation, X509Certificate2 cert, List<SignedItem> items, SignaturePolicy policy)
		{
			// create signature
			Xades xades = Xades.Create(XmlDocument, signatureLocation);
			xades.SignatureProperties.SigningTime = DateTime.UtcNow;
			// add policy
			if (policy != null)
			{
				xades.SignatureProperties.PolicyId = new ObjectIdentifier() { Identifier = policy.Identifier, Description = policy.Description };
				xades.SignatureProperties.PolicyURIs = new List<string>() { policy.URI };
				// TODO: determine transforms, calculate digest
			}
			// add document reference
			XadesReference reference = new XadesReference($"#xpointer(/)", TransformSet.Document.TransformChain);
			SignedItem signatureItem = items.Single(x => x.Type == SignedItemType.Document);
			if (policy != null && signatureItem.CommitmentType != null)
				reference.CommitmentTypeId = new ObjectIdentifier() { Identifier = signatureItem.CommitmentType.Identifier, Description = signatureItem.CommitmentType.Description };
			xades.References.Add(reference);
			// add other references
			foreach (SignedItem item in items.Where(x => x.Type != SignedItemType.Document))
			{
				reference = new XadesReference(item.Uri, item.Transform.TransformChain);
				if (policy != null && item.CommitmentType != null)
					reference.CommitmentTypeId = new ObjectIdentifier() { Identifier = signatureItem.CommitmentType.Identifier, Description = signatureItem.CommitmentType.Description };
				xades.References.Add(reference);
			}
			// sign
			string baseUri = XmlDocument.BaseURI;
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
