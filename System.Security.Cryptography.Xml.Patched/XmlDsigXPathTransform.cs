// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Xml;
using System.Xml.XPath;
using System.Xml.Xsl;

namespace System.Security.Cryptography.Xml.Patched
{
    // A class representing DSIG XPath Transforms

    public class XmlDsigXPathTransform : Transform
    {
        private Type[] _inputTypes = { typeof(Stream), typeof(XmlNodeList), typeof(XmlDocument) };
        private Type[] _outputTypes = { typeof(XmlNodeList) };
        private string _xpathexpr;
        private XmlDocument _document;
        private XmlNamespaceManager _nsm;
        private XPathContext _context;
        private string _placeholder;

        public XmlDsigXPathTransform()
        {
            Algorithm = SignedXml.XmlDsigXPathTransformUrl;
        }

        public XmlDsigXPathTransform(string xpath, params Collections.Generic.KeyValuePair<string, string>[] nsPairs) : this()
        {
            _xpathexpr = xpath;
            _nsm = new XmlNamespaceManager(new NameTable());
            foreach (Collections.Generic.KeyValuePair<string, string> pair in nsPairs)
                _nsm.AddNamespace(pair.Key, pair.Value);
        }

        public XmlDsigXPathTransform(string xpath, string creationPlaceholder, params Collections.Generic.KeyValuePair<string, string>[] nsPairs) : this(xpath, nsPairs)
        {
            _placeholder = creationPlaceholder;
        }

        public override Type[] InputTypes
        {
            get { return _inputTypes; }
        }

        public override Type[] OutputTypes
        {
            get { return _outputTypes; }
        }

        public override void LoadInnerXml(XmlNodeList nodeList)
        {
            // XPath transform is specified by text child of first XPath child
            if (nodeList == null)
                throw new CryptographicException(SR.Cryptography_Xml_UnknownTransform);

            foreach (XmlNode node in nodeList)
            {
                string prefix = null;
                string namespaceURI = null;
                XmlElement elem = node as XmlElement;
                if (elem != null)
                {
                    if (elem.LocalName == "XPath")
                    {
                        _xpathexpr = elem.InnerText.Trim(null);
                        _context = new XPathContext(elem);
                        XmlNodeReader nr = new XmlNodeReader(elem);
                        XmlNameTable nt = nr.NameTable;
                        _nsm = new XmlNamespaceManager(nt);
                        if (!Utils.VerifyAttributes(elem, (string)null))
                        {
                            throw new CryptographicException(SR.Cryptography_Xml_UnknownTransform);
                        }
                        // Look for a namespace in the attributes
                        foreach (XmlAttribute attrib in elem.Attributes)
                        {
                            if (attrib.Prefix == "xmlns")
                            {
                                prefix = attrib.LocalName;
                                namespaceURI = attrib.Value;
                                if (prefix == null)
                                {
                                    prefix = elem.Prefix;
                                    namespaceURI = elem.NamespaceURI;
                                }
                                _nsm.AddNamespace(prefix, namespaceURI);
                            }
                        }
                        break;
                    }
                    else
                    {
                        throw new CryptographicException(SR.Cryptography_Xml_UnknownTransform);
                    }
                }
            }

            if (_xpathexpr == null)
                throw new CryptographicException(SR.Cryptography_Xml_UnknownTransform);
        }

        protected override XmlNodeList GetInnerXml()
        {
            XmlDocument document = new XmlDocument();
            XmlElement element = document.CreateElement(null, "XPath", SignedXml.XmlDsigNamespaceUrl);

            if (_nsm != null)
            {
                // Add each of the namespaces as attributes of the element
                foreach (string prefix in _nsm)
                {
                    switch (prefix)
                    {
                        // Ignore the xml namespaces
                        case "xml":
                        case "xmlns":
                            break;

                        // Other namespaces
                        default:
                            // Ignore the default namespace
                            if (prefix != null && prefix.Length > 0)
                                element.SetAttribute("xmlns:" + prefix, _nsm.LookupNamespace(prefix));
                            break;
                    }
                }
            }
            // Add the XPath as the inner xml of the element
            element.InnerXml = _xpathexpr;
            document.AppendChild(element);
            return document.ChildNodes;
        }

        public override void LoadInput(object obj)
        {
            if (obj is Stream)
            {
                LoadStreamInput((Stream)obj);
            }
            else if (obj is XmlNodeList)
            {
                LoadXmlNodeListInput((XmlNodeList)obj);
            }
            else if (obj is XmlDocument)
            {
                LoadXmlDocumentInput((XmlDocument)obj);
            }
        }

        private void LoadStreamInput(Stream stream)
        {
            XmlResolver resolver = (ResolverSet ? _xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), BaseURI));
            XmlReader valReader = Utils.PreProcessStreamInput(stream, resolver, BaseURI);
            _document = new XmlDocument();
            _document.PreserveWhitespace = true;
            _document.Load(valReader);
        }

        private void LoadXmlNodeListInput(XmlNodeList nodeList)
        {
            // Use C14N to get a document
            XmlResolver resolver = (ResolverSet ? _xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), BaseURI));
            CanonicalXml c14n = new CanonicalXml((XmlNodeList)nodeList, resolver, true);
            using (MemoryStream ms = new MemoryStream(c14n.GetBytes()))
            {
                LoadStreamInput(ms);
            }
        }

        private void LoadXmlDocumentInput(XmlDocument doc)
        {
            _document = doc;
        }

        public override object GetOutput()
        {
            //CanonicalXmlNodeList resultNodeList = new CanonicalXmlNodeList();
            //if (!string.IsNullOrEmpty(_xpathexpr))
            //{
            //    XPathNavigator navigator = _document.CreateNavigator();
            //    XPathNodeIterator it = navigator.Select("//. | //@*");

            //    XPathExpression xpathExpr = navigator.Compile("boolean(" + _xpathexpr + ")");
            //    xpathExpr.SetContext(_nsm);

            //    while (it.MoveNext())
            //    {
            //        XmlNode node = ((IHasXmlNode)it.Current).GetNode();

            //        bool include = (bool)it.Current.Evaluate(xpathExpr);
            //        if (include == true)
            //            resultNodeList.Add(node);
            //    }

            //    // keep namespaces
            //    it = navigator.Select("//namespace::*");
            //    while (it.MoveNext())
            //    {
            //        XmlNode node = ((IHasXmlNode)it.Current).GetNode();
            //        resultNodeList.Add(node);
            //    }
            //}

            //return resultNodeList;
            (string xpath, XmlNamespaceManager nsm) = _context != null ? (_xpathexpr, _context) : (_placeholder, _nsm);
            return _document.SelectNodes($"(//. | //@* | //namespace::*)[{xpath}]", nsm);
        }

        public override object GetOutput(Type type)
        {
            if (type != typeof(XmlNodeList) && !type.IsSubclassOf(typeof(XmlNodeList)))
                throw new ArgumentException(SR.Cryptography_Xml_TransformIncorrectInputType, nameof(type));
            return (XmlNodeList)GetOutput();
        }

        internal class XPathContext : XsltContext, IXmlNamespaceResolver
        {
            private readonly XmlNode _hereNode;

            public XPathContext(XmlNode hereNode) : base()
            {
                _hereNode = hereNode;
            }

            public override bool Whitespace => true;
            public override int CompareDocument(string baseUri, string nextbaseUri) => 0;
            public override bool PreserveWhitespace(XPathNavigator node) => true;

            public override IXsltContextFunction? ResolveFunction(string prefix, string name, XPathResultType[] ArgTypes)
            {
                if (prefix.Length == 0 && name == "here")
                    return new HereFunction(_hereNode);
                return null;
            }

            public override IXsltContextVariable? ResolveVariable(string prefix, string name) => null;

            public override string LookupNamespace(string prefix)
            {
                if (!string.IsNullOrEmpty(prefix))
                {
                    string ns = _hereNode.GetNamespaceOfPrefix(prefix);
                    if (!string.IsNullOrEmpty(ns))
                        return ns;
                }
                return base.LookupNamespace(prefix);
            }

            public class HereFunction : IXsltContextFunction
            {
                private readonly XPathNodeIterator _iterator;

                public HereFunction(XmlNode node)
                {
                    _iterator = node.CreateNavigator().Select(".");
                }

                public int Minargs => 0;
                public int Maxargs => 0;
                public XPathResultType ReturnType => XPathResultType.NodeSet;
                public XPathResultType[] ArgTypes { get; } = new XPathResultType[0];

                public object Invoke(XsltContext xsltContext, object[] args, XPathNavigator docContext)
                {
                    return _iterator.Clone();
                }
            }
        }
    }
}
