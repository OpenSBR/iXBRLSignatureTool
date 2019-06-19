using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace OpenSBR.XAdES
{
	public class DigestAlgAndValue
	{
		public string Algorithm { get; set; }
		public byte[] Digest { get; set; }

		public XmlElement CreateXml(XmlElement parent, string name, string namespaceUri)
		{
			if (Algorithm == null || Digest == null)
				return null;

			XmlElement element = parent.CreateChild(name, namespaceUri);
			element.CreateChild("DigestMethod", SignedXml.XmlDsigNamespaceUrl).SetAttribute("Algorithm", Algorithm);
			element.CreateChild("DigestValue", SignedXml.XmlDsigNamespaceUrl, Convert.ToBase64String(Digest));
			return element;
		}

		public static DigestAlgAndValue TryParse(XmlElement element)
		{
			if (element == null)
				return null;

			DigestAlgAndValue result = new DigestAlgAndValue();
			result.Algorithm = element["DigestMethod", SignedXml.XmlDsigNamespaceUrl]?.GetAttribute("Algorithm");
			string hash = element["DigestValue", SignedXml.XmlDsigNamespaceUrl]?.Value;
			if (hash != null)
				result.Digest = Convert.FromBase64String(hash);
			return result;
		}
	}
}
