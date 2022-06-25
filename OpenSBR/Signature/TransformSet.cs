using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml.Patched;
using System.Xml;

namespace OpenSBR.Signature
{
	/// <summary>
	/// Structure for named transform chains
	/// </summary>
	public class TransformSet
	{
		public string Name { get; private set; }
		public TransformChain TransformChain { get; private set; }

		public TransformSet(string name, TransformChain transformChain)
		{
			Name = name;
			TransformChain = transformChain;
		}

		public TransformSet(string name, XmlElement element)
		{
			Name = name;

			TransformChain = new TransformChain();
			foreach (XmlElement xmlElement in element.ChildNodes)
			{
				string attribute = xmlElement.GetAttribute("Algorithm");
				Transform transform = CryptoConfig.CreateFromName(attribute) as Transform;
				if (transform != null)
				{
					transform.LoadInnerXml(xmlElement.ChildNodes);
					TransformChain.Add(transform);
				}
			}
		}

		private static TransformChain GetChain(params Transform[] transforms)
		{
			TransformChain chain = new TransformChain();
			foreach (Transform transform in transforms)
				chain.Add(transform);
			return chain;
		}

		// This implementation is different from the enveloped signature transform in the XmlDSig specification - the version defined in the specification would not allow for multiple independent signatures in the same document
		private static Transform GetEnvelopedSignatureTransform()
		{
			XmlDocument document = new XmlDocument();
			document.LoadXml("<ds:XPath xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">not(ancestor-or-self::ds:Signature)</ds:XPath>");
			XmlDsigXPathTransform transform = new XmlDsigXPathTransform();
			transform.LoadInnerXml(document.SelectNodes("/*"));
			return transform;
		}

		private static Transform GetUblEnvelopedSignatureTransform()
		{
			return new XmlDsigXPathTransform("count(ancestor-or-self::sig:UBLDocumentSignatures | here()/ancestor::sig:UBLDocumentSignatures[1]) > count(ancestor-or-self::sig:UBLDocumentSignatures)", "not(ancestor-or-self::sig:UBLDocumentSignatures)", new System.Collections.Generic.KeyValuePair<string, string>("sig", "urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2"));
			//XmlDocument document = new XmlDocument();
			//document.LoadXml("<ds:XPath xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:sig=\"urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2\">count(ancestor-or-self::sig:UBLDocumentSignatures | here()/ancestor::sig:UBLDocumentSignatures[1]) > count(ancestor-or-self::sig:UBLDocumentSignatures)</ds:XPath>");
			//XmlDsigXPathTransform transform = new XmlDsigXPathTransform();
			//transform.LoadInnerXml(document.SelectNodes("/*"));
			//return transform;
		}

		public static TransformSet Document = new TransformSet("Document transform", GetChain(GetEnvelopedSignatureTransform(), new XmlDsigC14NWithCommentsTransform()));
		public static TransformSet Signature = new TransformSet("Countersignature transform", GetChain(new XmlDsigExcC14NTransform()));

		public static TransformSet XMLFile = new TransformSet("XML file", GetChain(new XmlDsigC14NWithCommentsTransform()));
		public static TransformSet File = new TransformSet("File", (TransformChain)null);

		public static TransformSet EInvoice = new TransformSet("E-invoice transform", GetChain(GetUblEnvelopedSignatureTransform(), new XmlDsigC14NTransform()));
	}
}