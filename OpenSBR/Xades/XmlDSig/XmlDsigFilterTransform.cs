using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml.Patched;
using System.Xml;
using System.Xml.XPath;

namespace OpenSBR.XAdES
{
	public enum XmlDSigFilterType
	{
		intersect, subtract, union
	}

	/// <summary>
	/// XMLDSig filter transform class
	/// XPath 2.0 support relies on an external library
	/// </summary>
	public class XmlDsigFilterTransform : XmlDsigXPathTransform
	{
		public static readonly string AlgorithmURI = "http://www.w3.org/2002/06/xmldsig-filter2";

		#region Constructors

		public XmlDsigFilterTransform()
		{
			Algorithm = AlgorithmURI;
		}

		public XmlDsigFilterTransform(string xpath, XmlDSigFilterType filter, Dictionary<string, string> namespaces = null) : this()
		{
			XmlNamespaceManager nsMgr = new XmlNamespaceManager(new NameTable());
			if (namespaces != null)
				foreach (KeyValuePair<string, string> ns in namespaces)
					nsMgr.AddNamespace(ns.Key, ns.Value);
			_elements = new XmlDsigFilterElement[] { new XmlDsigFilterElement(xpath, filter, nsMgr) };
		}

		public XmlDsigFilterTransform(string[] xpath, XmlDSigFilterType[] filter, Dictionary<string, string> namespaces = null) : this()
		{
			XmlNamespaceManager nsMgr = new XmlNamespaceManager(new NameTable());
			if (namespaces != null)
				foreach (KeyValuePair<string, string> ns in namespaces)
					nsMgr.AddNamespace(ns.Key, ns.Value);
			if (xpath.Length != filter.Length)
				throw new Exception("Invalid transform parmeters");
			List<XmlDsigFilterElement> elements = new List<XmlDsigFilterElement>();
			for (int i = 0; i < xpath.Length; i++)
				elements.Add(new XmlDsigFilterElement(xpath[i], filter[i], nsMgr));
			_elements = elements.ToArray();
		}
		#endregion

		private XmlDsigFilterElement[] _elements;

		#region Parsing/storing expression from/to signature

		public override void LoadInnerXml(XmlNodeList nodeList)
		{
			if (nodeList == null)
				throw new CryptographicException("Unknown transform type");

			List<XmlDsigFilterElement> elements = new List<XmlDsigFilterElement>();
			foreach (XmlNode xmlNode in nodeList)
				elements.Add(new XmlDsigFilterElement(xmlNode as XmlElement));
			_elements = elements.ToArray();
		}

		protected override XmlNodeList GetInnerXml()
		{
			XmlDocument xmlDocument = new XmlDocument();
			foreach (XmlDsigFilterElement e in _elements)
				xmlDocument.AppendChild(e.GetInnerXml(xmlDocument));
			return xmlDocument.ChildNodes;
		}
		#endregion

		public override object GetOutput()
		{
			// Use reflection to access the _document field
			FieldInfo documentInfo = typeof(XmlDsigXPathTransform).GetField("_document", BindingFlags.NonPublic | BindingFlags.Instance);
			XmlDocument document = (XmlDocument)documentInfo.GetValue(this);

			CXmlNodeList cXmlNodeList = new CXmlNodeList();

			// From the Xades filter specification:
			// For each XPath expression X, in sequence, evaluate the expression and store the resulting node-set, S, along with the associated set operation.
			// Prepend a node-set consisting of just the document node, along with the operation union.
			// Create a new, empty filter node-set.
			// Process each node in the input node-set document, adding each node to the output node-set F if a flag Z is true. The flag is computed as follows:
			//   Z is true if and only if the node is present in any subtree-expanded union node-set and all subsequent subtree-expanded intersect node-sets but no subsequent subtree-expanded subtract node-sets, or false otherwise. If there are no subsequent intersect or subtract node-sets, then that part of the test is automatically passed.
			//   Presence in a subtree-expanded node-set can be efficiently determined without actually expanding the node-set, by simply maintaining a stack or count that identifies whether any nodes from that node-set are an ancestor of the node being processed.

			// build response
			foreach (XmlDsigFilterElement e in _elements)
				e.CreateSet(document);

			XPathNavigator navigator = document.CreateNavigator();
			XPathNodeIterator iterator = navigator.Select("//. | //@*");
			while (iterator.MoveNext())
			{
				XmlNode node = ((IHasXmlNode)iterator.Current).GetNode();
				bool include = true;
				// intersect: include = false if not in set, otherwise unchanged
				// subtract: include = false if in set, otherwise unchanged
				// union: include = true if in set, otherwise unchanged
				foreach (XmlDsigFilterElement e in _elements)
					include = e.Include(node) ?? include;
				if (include)
					cXmlNodeList.Add(node);
			}
			iterator = navigator.Select("//namespace::*");
			while (iterator.MoveNext())
				cXmlNodeList.Add(((IHasXmlNode)iterator.Current).GetNode());

			return cXmlNodeList;
		}

		private class CXmlNodeList : XmlNodeList
		{
			private List<XmlNode> nodeList;

			public CXmlNodeList()
			{
				nodeList = new List<XmlNode>();
			}

			public override int Count { get => nodeList.Count; }

			public override XmlNode Item(int index)
			{
				return nodeList[index];
			}

			public override IEnumerator GetEnumerator()
			{
				return nodeList.GetEnumerator();
			}

			public void Add(XmlNode node)
			{
				nodeList.Add(node);
			}
		}

		/// <summary>
		/// Private class for each element of a filter transform (intersect, subtract, union)
		/// </summary>
		private class XmlDsigFilterElement
		{
			public XmlDsigFilterElement(string xpath, XmlDSigFilterType filter, XmlNamespaceManager nsMgr)
			{
				_nsMgr = nsMgr;
				_xpath = xpath;
				_filter = filter;
			}

			private XmlNamespaceManager _nsMgr;
			private XmlDSigFilterType _filter;
			private string _xpath;
			private HashSet<XmlNode> _nodeSet;

			/// <summary>
			/// Create filter element from XML
			/// </summary>
			/// <param name="xmlElement"></param>
			public XmlDsigFilterElement(XmlElement xmlElement)
			{
				if (xmlElement != null && xmlElement.LocalName == "XPath" && xmlElement.NamespaceURI == AlgorithmURI)
				{
					string filter = xmlElement.Attributes["Filter"]?.Value;
					if (!Enum.TryParse(filter, out _filter))
						throw new CryptographicException("Invalid transform parameters");

					_xpath = xmlElement.InnerXml.Trim();
					XmlNodeReader nodeReader = new XmlNodeReader(xmlElement);
					_nsMgr = new XmlNamespaceManager(nodeReader.NameTable);

					foreach (XmlAttribute xmlAttribute in xmlElement.Attributes)
					{
						if (xmlAttribute.Prefix == "xmlns")
						{
							string text = xmlAttribute.LocalName;
							string uri = xmlAttribute.Value;
							if (text == null)
							{
								text = xmlElement.Prefix;
								uri = xmlElement.NamespaceURI;
							}
							_nsMgr.AddNamespace(text, uri);
						}
					}
				}
				if (_xpath == null)
					throw new CryptographicException("Unknown transform type");
			}

			/// <summary>
			/// Create XML node for this filter element
			/// </summary>
			/// <param name="doc"></param>
			/// <returns></returns>
			public XmlElement GetInnerXml(XmlDocument doc)
			{
				XmlElement xmlElement = doc.CreateElement(null, "XPath", AlgorithmURI);
				if (_nsMgr != null)
				{
					foreach (string text in _nsMgr)
						if (!(text == "xml") && !(text == "xmlns") && text != null && text.Length > 0)
							xmlElement.SetAttribute("xmlns:" + text, _nsMgr.LookupNamespace(text));
				}
				xmlElement.InnerXml = _xpath;
				xmlElement.SetAttribute("Filter", _filter.ToString("f"));
				return xmlElement;
			}

			/// <summary>
			/// Initialise subset for this filter element
			/// </summary>
			/// <param name="navigator">Root of document</param>
			public void CreateSet(XmlDocument document)
			{
				_nodeSet = new HashSet<XmlNode>(document.SelectNodes(_xpath, _nsMgr).OfType<XmlNode>());
			}

			/// <summary>
			/// Determines whether a node is in the selection
			/// </summary>
			/// <param name="navigator"></param>
			/// <returns></returns>
			private bool IsInSet(XmlNode node)
			{
				return _nodeSet.Contains(node) || (node is XmlAttribute a ? IsInSet(a.OwnerElement) : node.ParentNode != null && IsInSet(node.ParentNode));
			}

			/// <summary>
			/// Determine whether and how a node is affected by this element
			/// </summary>
			/// <param name="navigator"></param>
			/// <returns></returns>
			public bool? Include(XmlNode node)
			{
				bool inSet = IsInSet(node);
				switch (_filter)
				{
					case XmlDSigFilterType.intersect:
						if (!inSet)
							return false;
						break;
					case XmlDSigFilterType.subtract:
						if (inSet)
							return false;
						break;
					case XmlDSigFilterType.union:
						if (inSet)
							return true;
						break;
				}
				return null;
			}
		}
	}
}
