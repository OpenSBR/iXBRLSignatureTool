﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace SignXBRL
{
	public static class Utils
	{
		/// <summary>
		/// List all certificate with a private key and usage non-repudiation
		/// </summary>
		/// <returns></returns>
		public static X509Certificate2Collection GetCertificates()
		{
			using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
			{
				store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
				X509Certificate2Collection collection = store.Certificates.Find(X509FindType.FindByKeyUsage, X509KeyUsageFlags.NonRepudiation, true);
				for (int i = collection.Count - 1; i >= 0; i--)
					if (!collection[i].HasPrivateKey)
						collection.RemoveAt(i);
				return collection;
			}
		}
	}

	public static class Extensions
	{
		public static IEnumerable<string> GetFiles(this DragEventArgs e)
		{
			if (e.Data != null)
			{
				string[] files = e.Data.GetData(DataFormats.FileDrop) as string[];
				if (files != null)
				{
					foreach (string file in files)
						yield return file;
					yield break;
				}
				string uri = e.Data.GetData(DataFormats.StringFormat) as string;
				if (uri != null)
					yield return uri;
			}
		}

		public static string SubjectInfo(this X509Certificate2 certificate)
		{
			StringBuilder sb = new StringBuilder();
			Dictionary<string, string> subject = certificate.SubjectName.SplitName();
			string role = certificate.GLEIFRole() ?? subject.Join(", ", "T");
			string name = subject.Join(", ", "CN") ?? subject.Join(" ", "G", "SN");
			if (name != null)
				sb.AppendLine(role == null ? name : $"{name}, {role}");
			if (subject.TryGetValue("O", out string org))
				sb.AppendLine(org);
			string loc = subject.Join(", ", "L", "S", "C");
			if (loc != null)
				sb.AppendLine(loc);

			string lei = certificate.GLEIFLEI();
			if (lei != null)
				sb.AppendLine($"LEI: {lei}");

			return sb.ToString().Trim();
		}

		public static string IssuerInfo(this X509Certificate2 certificate)
		{
			StringBuilder sb = new StringBuilder();
			Dictionary<string, string> issuer = certificate.IssuerName.SplitName();
			string name = issuer.Join(", ", "CN", "O");
			if (name != null)
				sb.AppendLine(name);
			string loc = issuer.Join(", ", "L", "S", "C");
			if (loc != null)
				sb.AppendLine(loc);

			return sb.ToString().Trim();
		}

		private static string Join<TKey, T>(this Dictionary<TKey, T> dictionary, string separator, params TKey[] keys)
		{
			List<string> list = new List<string>();
			foreach (TKey key in keys)
				if (dictionary.TryGetValue(key, out T value))
					list.Add(value.ToString());
			return list.Count > 0 ? String.Join(separator, list) : null;
		}

		private static System.Text.RegularExpressions.Regex indexRegex = new System.Text.RegularExpressions.Regex("([A-Z]+)=([^,]+)");
		public static Dictionary<string, string> SplitName(this X500DistinguishedName distinguishedName)
		{
			return indexRegex.Matches(distinguishedName.Name).OfType<System.Text.RegularExpressions.Match>().ToDictionary(x => x.Groups[1].Value, x => x.Groups[2].Value);
		}

		public static string GLEIFLEI(this X509Certificate2 certificate)
		{
			X509Extension leiExtension = certificate.Extensions.OfType<X509Extension>().FirstOrDefault(x => x.Oid.Value == "1.3.6.1.4.1.52266.1");
			if (leiExtension == null || (leiExtension.RawData[0] != 0xc && leiExtension.RawData[0] != 0x13))
				return null;
			return Encoding.UTF8.GetString(leiExtension.RawData, 2, leiExtension.RawData[1]);
		}

		public static string GLEIFRole(this X509Certificate2 certificate)
		{
			X509Extension roleExtension = certificate.Extensions.OfType<X509Extension>().FirstOrDefault(x => x.Oid.Value == "1.3.6.1.4.1.52266.2");
			if (roleExtension == null || (roleExtension.RawData[0] != 0xc && roleExtension.RawData[0] != 0x13))
				return null;
			return Encoding.UTF8.GetString(roleExtension.RawData, 2, roleExtension.RawData[1]);
		}
	}
}
