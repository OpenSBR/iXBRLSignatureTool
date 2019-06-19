using System;
using System.Collections.Generic;
using System.Xml;

namespace OpenSBR
{
	internal static class Extensions
	{
		internal static XmlElement CreateChild(this XmlNode node, string name, string namespaceURI, string content = null)
		{
			XmlElement child = node.OwnerDocument.CreateElement(name, namespaceURI);
			if (content != null)
				child.InnerText = content;
			node.AppendChild(child);
			return child;
		}
	}
}
