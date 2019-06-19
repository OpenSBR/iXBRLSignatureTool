using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;

namespace OpenSBR.Signature
{
	internal static class Extensions
	{
		public static XmlElement GetOrCreate(this XmlElement element, string name, string namespaveUri)
		{
			XmlElement child = element[name, namespaveUri];
			if (child == null)
			{
				child = element.OwnerDocument.CreateElement(name, namespaveUri);
				element.AppendChild(child);
			}
			return child;
		}
	}
}
