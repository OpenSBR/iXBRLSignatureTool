using OpenSBR.XAdES;
using System;
using System.Linq;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace OpenSBR.Signature
{
	public enum SignedItemType
	{
		Document,
		Signature,
		Fragment,
		File
	}

	/// <summary>
	/// Description of a signed reference, including the commitment type
	/// </summary>
	public class SignedItem
	{
		public SignedItemType Type { get; set; }     // document, parent signature, external item, fragment

		public string Uri { get; set; }		// uri or null
		public TransformSet Transform { get; set; }

		public SignaturePolicy.CommitmentType CommitmentType { get; set; }

		public bool IsValid { get; }

		public SignedItem()
		{ }

		internal SignedItem(XmlElement signatureElement, XadesReference reference, SignaturePolicy signaturePolicy)
		{
			// determine type from reference uri
			Uri = reference.URI;
			if (Uri == "" || Uri == "#xpointer(/)")
				Type = SignedItemType.Document;
			else if (reference.Type == Xades.CounterSignatureRefernceType)
				Type = SignedItemType.Signature;
			else if (Uri[0] == '#')
			{
				string idref = Uri.Substring(1);
				XmlElement node = signatureElement.OwnerDocument.SelectSingleNode("//*[@id='" + idref + "' or @Id='" + idref + "']") as XmlElement;
				if (node != null && node.LocalName == "SignatureValue" && node.NamespaceURI == SignedXml.XmlDsigNamespaceUrl)
					Type = SignedItemType.Signature;
				else
					Type = SignedItemType.Fragment;
			}
			else
				Type = SignedItemType.File;

			// store transform
			Transform = new TransformSet(null, reference.TransformChain);
			// find or add commitment type in/to policy
			if (reference.CommitmentTypeId != null)
			{
				SignaturePolicy.CommitmentType commitmentType = signaturePolicy.CommitmentTypes.FirstOrDefault(x => x.Identifier == reference.CommitmentTypeId.Identifier);
				if (commitmentType == null)
				{
					commitmentType = new SignaturePolicy.CommitmentType() { Identifier = reference.CommitmentTypeId.Identifier, Description = reference.CommitmentTypeId.Description };
					signaturePolicy.CommitmentTypes.Add(commitmentType);
				}
				CommitmentType = commitmentType;
			}

			IsValid = reference.IsValid;
		}
	}
}