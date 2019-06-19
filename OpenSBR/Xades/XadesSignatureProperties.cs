using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace OpenSBR.XAdES
{
	public class XadesSignatureProperties
	{
		public DateTime? SigningTime { get; set; }

		public string CertificateDigest { get; set; }

		public bool IncludeSigningCertificate { get; set; }
		public bool PolicyImplied { get; set; }
		public ObjectIdentifier PolicyId { get; set; }
		public TransformChain PolicyTransformChain { get; set; }

		public string PolicyDigestMethod { get; set; }
		public byte[] PolicyDigest { get; set; }

		public List<string> PolicyURIs { get; set; }
		public List<PolicyUserNotice> PolicyNotices { get; set; }

		internal XadesSignatureProperties()
		{
			CertificateDigest = SignedXml.XmlDsigSHA1Url; //.XmlDsigSHA256Url;
			IncludeSigningCertificate = true;
		}

		/// <summary>
		/// Create signature properties from existing document
		/// </summary>
		/// <param name="element"></param>
		/// <param name="nsm"></param>
		internal XadesSignatureProperties(XmlElement element, XmlNamespaceManager nsm)
		{
			// read from xml
			XmlElement signedSignatureProperties = element["SignedSignatureProperties", Xades.XadesNamespaceUrl];

			// signing time
			if (DateTime.TryParse(signedSignatureProperties?["SigningTime", Xades.XadesNamespaceUrl]?.InnerText, out DateTime signingTime))
				SigningTime = signingTime;

			// signing certificate; currently only one certificate supported
			//foreach (XmlElement cert in element.SelectNodes("xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert", nsm))
			//{
			// TODO: read certificate information and expose as public read-only array
			//}

			// signature policy
			XmlElement signaturePolicyIdentifier = signedSignatureProperties["SignaturePolicyIdentifier", Xades.XadesNamespaceUrl];
			XmlElement signaturePolicyImplied = signaturePolicyIdentifier?["SignaturePolicyImplied", Xades.XadesNamespaceUrl];
			XmlElement signaturePolicyId = signaturePolicyIdentifier?["SignaturePolicyId", Xades.XadesNamespaceUrl];
			if (signaturePolicyImplied != null)
				PolicyImplied = true;
			else if (signaturePolicyId != null)
			{
				PolicyId = ObjectIdentifier.TryParseFromParent(signaturePolicyId, "SigPolicyId", Xades.XadesNamespaceUrl);

				XmlElement transformChain = signaturePolicyId.SelectSingleNode("ds:Transforms", nsm) as XmlElement;
				if (transformChain != null)
				{
					PolicyTransformChain = new TransformChain();
					MethodInfo loadXmlInfo = typeof(TransformChain).GetMethod("LoadXml", BindingFlags.NonPublic | BindingFlags.Instance);
					loadXmlInfo.Invoke(PolicyTransformChain, new object[] { transformChain });
				}

				DigestAlgAndValue digestInfo = DigestAlgAndValue.TryParse(signaturePolicyId["SigPolicyHash", Xades.XadesNamespaceUrl]);
				PolicyDigestMethod = digestInfo.Algorithm;
				PolicyDigest = digestInfo.Digest;

				XmlElement signaturePolicyQualifiers = signaturePolicyIdentifier["SigPolicyQualifiers", Xades.XadesNamespaceUrl];
				if (signaturePolicyQualifiers != null)
				{
					PolicyURIs = signaturePolicyQualifiers.SelectNodes("xades:SigPolicyQualifier/xades:SPURI", nsm).OfType<XmlElement>().Select(x => x.InnerText).ToList();
					//PolicyNotices = signaturePolicyQualifiers.SelectNodes("xades:SigPolicyQualifier/xades:SPUserNotice", nsm).OfType<XmlElement>().Select(x => new PolicyUserNotice(x)).ToList();
				}
			}
		}

		/// <summary>
		/// Update hash value from stream
		/// </summary>
		/// <param name="stream"></param>
		public void CalculatePolicyHash(Stream stream)
		{
			PolicyDigest = XadesUtils.CalculateHash(stream, PolicyTransformChain, PolicyDigestMethod);
		}

		/// <summary>
		/// Update hash value from document at URI
		/// </summary>
		/// <param name="uri"></param>
		public void CalculatePolicyHash(string uri)
		{
			using (WebClient wc = new WebClient())
				using (Stream stream = wc.OpenRead(uri))
					CalculatePolicyHash(stream);
		}

		/// <summary>
		/// Create <SignedSignatureProperties>
		/// </summary>
		/// <param name="document"></param>
		/// <returns></returns>
		internal XmlElement CreateXadesSignatureProperties(XmlDocument document, X509Certificate2 certificate, SignatureType xadesVersion)
		{
			XmlElement signatureProperties = document.CreateElement("SignedSignatureProperties", Xades.XadesNamespaceUrl);

			// signing time; required for 1.1.1
			if (SigningTime.HasValue || xadesVersion < SignatureType.Xades132)
				signatureProperties.CreateChild("SigningTime", Xades.XadesNamespaceUrl, (SigningTime ?? DateTime.Now).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"));
			// signing certificate; can be omitted >= 1.3.2
			if (IncludeSigningCertificate || xadesVersion < SignatureType.Xades132)
			{
				XmlElement signingCertificate = signatureProperties.CreateChild("SigningCertificate", Xades.XadesNamespaceUrl);
				XmlElement signingCert = signingCertificate.CreateChild("Cert", Xades.XadesNamespaceUrl);
				// certificate digest
				HashAlgorithm hashAlg = CryptoConfig.CreateFromName(CertificateDigest) as HashAlgorithm;
				if (hashAlg == null)
					throw new CryptographicException("Invalid digest method");
				DigestAlgAndValue certDigest = new DigestAlgAndValue() { Algorithm = CertificateDigest, Digest = hashAlg.ComputeHash(certificate.RawData) };
				signingCert.AppendChild(certDigest.CreateXml(signingCert, "CertDigest", Xades.XadesNamespaceUrl));
				// certificate issuer
				XmlElement issuerSerial = signingCert.CreateChild("IssuerSerial", Xades.XadesNamespaceUrl);
				issuerSerial.CreateChild("X509IssuerName", SignedXml.XmlDsigNamespaceUrl, certificate.Issuer);
				issuerSerial.CreateChild("X509SerialNumber", SignedXml.XmlDsigNamespaceUrl, XadesUtils.ToDecimal(XadesUtils.HexToBytes(certificate.SerialNumber)));
			}
			// signature policy; can be omitted >= 1.3.2
			XmlElement sigPolicyId = PolicyId?.GetObjectIdentifier(document, "SigPolicyId", Xades.XadesNamespaceUrl);
			if (PolicyImplied || xadesVersion < SignatureType.Xades132 || sigPolicyId != null)
			{
				XmlElement signaturePolicyIdentifier = signatureProperties.CreateChild("SignaturePolicyIdentifier", Xades.XadesNamespaceUrl);
				// policy implied if specified (or policyid not specified)
				if (PolicyImplied || sigPolicyId == null)
					signaturePolicyIdentifier.CreateChild("SignaturePolicyImplied", Xades.XadesNamespaceUrl);
				else if (sigPolicyId != null)
				{
					XmlElement signaturePolicyId = signaturePolicyIdentifier.CreateChild("SignaturePolicyId", Xades.XadesNamespaceUrl);
					signaturePolicyId.AppendChild(sigPolicyId);

					if (PolicyTransformChain != null && PolicyTransformChain.Count > 0)
					{
						MethodInfo getXmlInfo = typeof(TransformChain).GetMethod("GetXml", BindingFlags.NonPublic | BindingFlags.Instance);
						signaturePolicyId.AppendChild((XmlElement)getXmlInfo.Invoke(PolicyTransformChain, new object[] { document, SignedXml.XmlDsigNamespaceUrl }));
					}

					if (PolicyDigest == null)
						CalculatePolicyHash(PolicyURIs.FirstOrDefault() ?? PolicyId.Identifier);

					DigestAlgAndValue policyHash = new DigestAlgAndValue() { Algorithm = PolicyDigestMethod, Digest = PolicyDigest };
					policyHash.CreateXml(signaturePolicyId, "SigPolicyHash", Xades.XadesNamespaceUrl);

					XmlElement sigPolicyQualifiers = document.CreateElement("SigPolicyQualifiers", Xades.XadesNamespaceUrl);
					if (PolicyURIs != null && PolicyURIs.Count > 0)
						foreach (string uri in PolicyURIs)
							sigPolicyQualifiers.CreateChild("SigPolicyQualifier", Xades.XadesNamespaceUrl).CreateChild("SPURI", Xades.XadesNamespaceUrl, uri);
					if (PolicyNotices != null && PolicyNotices.Count > 0)
						foreach (PolicyUserNotice notice in PolicyNotices)
							notice.CreateXml(sigPolicyQualifiers.CreateChild("SigPolicyQualifier", Xades.XadesNamespaceUrl));
					if (sigPolicyQualifiers.ChildNodes.Count > 0)
						signaturePolicyId.AppendChild(sigPolicyQualifiers);
				}
			}
			return signatureProperties;
		}

		/// <summary>
		/// Check signature policy hash
		/// </summary>
		/// <param name="stream"></param>
		/// <returns></returns>`
		public bool CheckPolicyHash(Stream stream)
		{
			byte[] digest = XadesUtils.CalculateHash(stream, PolicyTransformChain, PolicyDigestMethod);
			return digest.SequenceEqual(PolicyDigest);
		}

		/// <summary>
		/// Check signature policy hash
		/// </summary>
		/// <param name="uri"></param>
		/// <returns></returns>
		public bool CheckPolicyHash(string uri = null)
		{
			using (WebClient wc = new WebClient())
				using (Stream stream = wc.OpenRead(uri ?? PolicyURIs.FirstOrDefault() ?? PolicyId.Identifier))
					return CheckPolicyHash(stream);
		}
	}
}
