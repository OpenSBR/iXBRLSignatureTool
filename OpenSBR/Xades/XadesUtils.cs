using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace OpenSBR.XAdES
{
	public class XadesUtils
	{
		/// <summary>
		/// Calculate hash
		/// </summary>
		/// <param name="obj">Stream, XmlNodeList or XmlDocument</param>
		/// <param name="transformChain"></param>
		/// <param name="digestMethod"></param>
		/// <returns></returns>
		internal static byte[] CalculateHash(object obj, TransformChain transformChain, string digestMethod)
		{
			if (!(obj is Stream) && !(obj is XmlNodeList) && !(obj is XmlDocument))
				throw new CryptographicException("Invalid data type");

			Stream stream = obj as Stream;
			if (transformChain != null && transformChain.Count > 0)
			{
				MethodInfo mi = typeof(TransformChain).GetMethod("TransformToOctetStream", BindingFlags.NonPublic | BindingFlags.Instance, null, new Type[] { typeof(object), typeof(Type), typeof(XmlResolver), typeof(string) }, null);
				stream = (Stream)mi.Invoke(transformChain, new object[] { obj, obj.GetType(), null, "" });
			}
			if (stream == null)
				throw new CryptographicException("Invalid data type");

			HashAlgorithm hashAlg = CryptoConfig.CreateFromName(digestMethod) as HashAlgorithm;
			if (hashAlg == null)
				throw new CryptographicException("Invalid digest method");
			return hashAlg.ComputeHash(stream);
		}

		internal static byte[] HexToBytes(string str)
		{
			int len = str.Length;
			if (len % 2 == 1)
			{
				str = $"0{str}";
				len++;
			}
			byte[] b = new byte[len >> 1];
			for (int i = 0; i < len; i += 2)
				b[i >> 1] = Convert.ToByte(str.Substring(i, 2), 16);
			return b;
		}

		/// <summary>
		/// Convert a byte array to a decimal string ([0] msb ..... [x] lsb)
		/// </summary>
		/// <param name="num"></param>
		/// <returns></returns>
		internal static string ToDecimal(byte[] num)
		{
			byte[] n = (byte[])num.Clone();
			int len = n.Length;

			List<char> digits = new List<char>();
			while (n.Any(x => x != 0))
			{
				int rem = 0;
				for (int i = 0; i < len; i++)
				{
					int a = rem * 256 + n[i];
					n[i] = (byte)Math.DivRem(a, 10, out rem);
				}
				digits.Add((char)(rem + '0'));
			}
			if (digits.Count == 0)
				digits.Add('0');
			digits.Reverse();
			return new string(digits.ToArray());
		}
	}
}
