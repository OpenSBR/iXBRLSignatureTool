using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography.Xml.Patched;
using System.Xml;

namespace OpenSBR.XAdES
{
	public class XadesReference
	{
		public string Id { get; set; }
		public string URI { get; set; }
		public string Type { get; set; }
		public XmlElement Fragment { get; private set; }
		public TransformChain TransformChain { get; set; }
		public string DigestMethod { get; set; }

		public string Description { get; set; }
		public ObjectIdentifier ObjectIdentifier { get; set; }
		public string MimeType { get; set; }
		public string Encoding { get; set; }

		public ObjectIdentifier CommitmentTypeId { get; set; }
		public List<XmlElement> CommitmentTypeQualifiers { get; set; }

		public bool IsValid { get; internal set; }

		/// <summary>
		/// Create new document reference
		/// </summary>
		/// <param name="uri"></param>
		/// <param name="transformChain"></param>
		/// <param name="digestMethod"></param>
		public XadesReference(string uri, TransformChain transformChain = null, string digestMethod = null)
		{
			URI = uri;
			TransformChain = transformChain;
			DigestMethod = digestMethod ?? SignedXml.XmlDsigSHA256Url;

			CommitmentTypeQualifiers = new List<XmlElement>();
		}

		public XadesReference(string id, XmlElement fragment, TransformChain transformChain = null, string digestMethod = null) : this(id.StartsWith("#") ? id : $"#{id}", transformChain, digestMethod)
		{
			Fragment = fragment;
		}

		/// <summary>
		/// Create new instance from Reference (from existing document)
		/// </summary>
		/// <param name="reference"></param>
		internal XadesReference(Reference reference)
		{
			Id = reference.Id;
			URI = Uri.UnescapeDataString(reference.Uri);
			Type = reference.Type;
			TransformChain = reference.TransformChain;
			DigestMethod = reference.DigestMethod;
		}

		/// <summary>
		/// Create Reference for this document
		/// </summary>
		/// <param name="resolver"></param>
		/// <returns></returns>
		internal Reference GetReference(Xades.UriResolverDelegate resolver = null)
		{
			Stream stream = (resolver != null && !string.IsNullOrEmpty(URI) && !URI.StartsWith("#")) ? resolver(URI) : null;
			Reference reference = (stream != null) ? new Reference(stream) : new Reference(URI);

			reference.Uri = URI;
			reference.Type = Type;
			reference.TransformChain = TransformChain ?? new TransformChain();
			reference.DigestMethod = DigestMethod;
			reference.Id = Id;

			return reference;
		}

		/// <summary>
		/// Create <DataObjectFormat> for this item
		/// </summary>
		/// <param name="document"></param>
		/// <returns></returns>
		internal XmlElement AddObjectFormat(XmlElement signedDataObjectProperties)
		{
			XmlElement objectIdentifier = ObjectIdentifier?.GetObjectIdentifier(signedDataObjectProperties.OwnerDocument);
			if (Description == null || objectIdentifier == null || MimeType == null)
				return null;

			XmlElement objectFormat = signedDataObjectProperties.CreateChild("DataObjectFormat", Xades.XadesNamespaceUrl);
			objectFormat.SetAttribute("ObjectReference", $"#{Id}");

			if (objectIdentifier != null)
				objectFormat.AppendChild(objectIdentifier);
			if (MimeType != null)
				objectFormat.CreateChild("MimeType", Xades.XadesNamespaceUrl, MimeType);
			if (Encoding != null)
				objectFormat.CreateChild("Encoding", Xades.XadesNamespaceUrl, Encoding);
			return objectFormat;
		}

		/// <summary>
		/// Create <CommitmentTypeIndication> for this item
		/// </summary>
		/// <param name="document"></param>
		/// <returns></returns>
		internal XmlElement AddCommitmentTypeIndication(XmlElement signedDataObjectProperties)
		{
			XmlElement commitmentIdentifier = CommitmentTypeId?.GetObjectIdentifier(signedDataObjectProperties.OwnerDocument, "CommitmentTypeId", Xades.XadesNamespaceUrl);
			if (commitmentIdentifier == null)
				return null;

			XmlElement commitmentTypeIndication = signedDataObjectProperties.CreateChild("CommitmentTypeIndication", Xades.XadesNamespaceUrl);
			commitmentTypeIndication.AppendChild(commitmentIdentifier);
			commitmentTypeIndication.CreateChild("ObjectReference", Xades.XadesNamespaceUrl, $"#{Id}");
			if (CommitmentTypeQualifiers != null && CommitmentTypeQualifiers.Count > 0)
			{
				XmlElement commitmentTypeQualifiers = commitmentTypeIndication.CreateChild("CommitmentTypeQualifiers", Xades.XadesNamespaceUrl);
				foreach (XmlElement commitmentTypeQualifier in CommitmentTypeQualifiers.Where(x => x.LocalName == "CommitmentTypeQualifier" && x.NamespaceURI == Xades.XadesNamespaceUrl))
					commitmentTypeQualifiers.AppendChild(signedDataObjectProperties.OwnerDocument.ImportNode(commitmentTypeQualifier, true));
			}
			return commitmentTypeIndication;
		}

		internal void AddObjectReference(XmlElement commitmentTypeIndication)
		{
			XmlElement reference = commitmentTypeIndication.OwnerDocument.CreateElement("ObjectReference", Xades.XadesNamespaceUrl);
			reference.Value = $"#{Id}";
			XmlElement commitmentTypeQualifiers = commitmentTypeIndication["CommitmentTypeQualifiers", Xades.XadesNamespaceUrl];
			if (commitmentTypeQualifiers != null)
				commitmentTypeIndication.InsertBefore(reference, commitmentTypeQualifiers);
			else
				commitmentTypeIndication.AppendChild(reference);
		}

		/// <summary>
		/// Parse the DataObjectFormat and CommitmentTypeIndication properties for this document id
		/// </summary>
		/// <param name="element"></param>
		/// <param name="nsm"></param>
		internal void ParseProperties(XmlElement element, XmlNamespaceManager nsm)
		{
			// data object format
			XmlElement objectFormat = element.SelectSingleNode($"xades:SignedDataObjectProperties/xades:DataObjectFormat[@ObjectReference='#{Id}']", nsm) as XmlElement;
			if (objectFormat != null)
			{
				Description = objectFormat["Description", Xades.XadesNamespaceUrl]?.InnerText;
				ObjectIdentifier = ObjectIdentifier.TryParseFromParent(objectFormat);

				MimeType = objectFormat["MimeType", Xades.XadesNamespaceUrl]?.InnerText;
				Encoding = objectFormat["Encoding", Xades.XadesNamespaceUrl]?.InnerText;
			}

			// commitment type indication
			XmlElement commitmentTypeIndication = element.SelectSingleNode($"xades:SignedDataObjectProperties/xades:CommitmentTypeIndication[xades:ObjectReference='#{Id}']", nsm) as XmlElement;
			if (commitmentTypeIndication != null)
			{
				CommitmentTypeId = ObjectIdentifier.TryParseFromParent(commitmentTypeIndication, "CommitmentTypeId", Xades.XadesNamespaceUrl);
				XmlElement commitmentTypeQualifiers = commitmentTypeIndication["COmmitmentTypeQualifiers", Xades.XadesNamespaceUrl];
				if (commitmentTypeQualifiers != null)
					foreach (XmlElement commitmentTypeQualifier in commitmentTypeQualifiers.GetElementsByTagName("CommitmentTypeQualifier", Xades.XadesNamespaceUrl))
						CommitmentTypeQualifiers.Add(commitmentTypeQualifier);
			}
		}
	}
}
