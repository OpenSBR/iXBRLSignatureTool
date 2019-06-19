using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace OpenSBR.XAdES
{
	// Fix to include id's in data object descendants.
	// The .NET implementation does not include these by default. This implementation returns a copy of the fragment, wrapped in a parent element with all namespace declarations and xml-namespace attributes from the signature context.
	internal class XadesSignedXml : SignedXml
	{
		private Dictionary<string, XmlElement> _idIndex = new Dictionary<string, XmlElement>();
		private XmlElement _signatureParent;

		public XadesSignedXml(XmlDocument document) : base(document)
		{ }

		public XadesSignedXml(XmlElement elem) : base(elem)
		{
			_signatureParent = elem;
		}

		public void AddXadesObject(DataObject dataObject)
		{
			base.AddObject(dataObject);
			_idIndex = dataObject.Data.OfType<XmlElement>().SelectMany(x => x.SelectNodes("//@id | //@Id").OfType<XmlAttribute>()).ToDictionary(x => x.Value, x => x.OwnerElement);
		}

		public override XmlElement GetIdElement(XmlDocument document, string idValue)
		{
			if (_idIndex.TryGetValue(idValue, out XmlElement element))
			{
				XmlElement copy = (XmlElement)element.CloneNode(true);
				XmlElement parent = document.CreateElement("parent");
				parent.AppendChild(copy);
				for (XmlElement node = _signatureParent; node != null; node = node.ParentNode as XmlElement)
				{
					foreach (XmlAttribute attribute in node.Attributes)
					{
						if (attribute.Prefix == "xmlns" || attribute.Prefix == "xml")
						{
							if (!parent.HasAttribute(attribute.Name))
								parent.SetAttribute(attribute.Name, attribute.Value);
						}
					}
				}
				return copy;
			}
			return base.GetIdElement(document, idValue);
		}
	}
}
