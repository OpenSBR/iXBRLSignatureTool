using OpenSBR.XAdES;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace OpenSBR.Signature
{
	/// <summary>
	/// Signature policy, containing one or more commitment types
	/// </summary>
	public class SignaturePolicy
	{
		public string Identifier { get; set; }
		public string Description { get; set; }
		public List<string> DocumentationReferences { get; } = new List<string>();

		public string URI { get; set; }
		public List<CommitmentType> CommitmentTypes { get; } = new List<CommitmentType>();

		public bool IsValid { get; set; }

		public class CommitmentType
		{
			public string Identifier { get; set; }
			public string Description { get; set; }
		}

		public SignaturePolicy()
		{
		}

		internal SignaturePolicy(ObjectIdentifier objectIdentifier)
		{
			Identifier = objectIdentifier.Identifier;
			Description = objectIdentifier.Description;
			DocumentationReferences = objectIdentifier.DocumentationReferences.ToList();
		}

		public override string ToString()
		{
			return Identifier;
		}
	}
}
