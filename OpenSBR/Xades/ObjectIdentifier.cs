using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;

namespace OpenSBR.XAdES
{
	public class ObjectIdentifier
	{
		public string Identifier { get; set; }
		public string Description { get; set; }
		public List<string> DocumentationReferences { get; } = new List<string>();

		internal XmlElement GetObjectIdentifier(XmlDocument document, string name = "ObjectIdentifier", string namespaceUri = null)
		{
			if (Identifier == null)
				return null;

			XmlElement objectIdentifier = document.CreateElement(name, namespaceUri ?? Xades.XadesNamespaceUrl);
			if (Identifier != null)
				objectIdentifier.CreateChild("Identifier", Xades.XadesNamespaceUrl, Identifier);
			if (Description != null)
				objectIdentifier.CreateChild("Description", Xades.XadesNamespaceUrl, Description);
			if (DocumentationReferences.Count > 0)
			{
				XmlElement documentationReferences = objectIdentifier.CreateChild("DocumentationReferences", Xades.XadesNamespaceUrl);
				foreach (string documentationReference in DocumentationReferences)
					documentationReferences.CreateChild("DocumentationReference", Xades.XadesNamespaceUrl, documentationReference);
			}
			return objectIdentifier;
		}

		internal static ObjectIdentifier TryParseFromParent(XmlElement parent, string name = "ObjectIdentifier", string namespaceUri = null)
		{
			return TryParse(parent[name, namespaceUri ?? Xades.XadesNamespaceUrl]);
		}

		internal static ObjectIdentifier TryParse(XmlElement element)
		{
			if (element == null)
				return null;

			ObjectIdentifier result = new ObjectIdentifier();
			result.Identifier = element["Identifier", Xades.XadesNamespaceUrl]?.InnerText;
			result.Description = element["Description", Xades.XadesNamespaceUrl]?.InnerText;

			XmlElement documentationReferences = element["DocumentationReferences", Xades.XadesNamespaceUrl];
			if (documentationReferences != null)
				foreach (XmlElement documentationReference in documentationReferences.GetElementsByTagName("DocumentationReference", Xades.XadesNamespaceUrl).OfType<XmlElement>())
					result.DocumentationReferences.Add(documentationReference.InnerText);
			return result;
		}

		public override string ToString()
		{
			return Description == null ? Identifier : $"{Identifier} - {Description}";
		}
	}
}
