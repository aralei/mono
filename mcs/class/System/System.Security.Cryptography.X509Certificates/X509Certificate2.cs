//
// System.Security.Cryptography.X509Certificate2 class
//
// Author:
//	Sebastien Pouliot  <sebastien@ximian.com>
//
// (C) 2003 Motus Technologies Inc. (http://www.motus.com)
// Copyright (C) 2004-2006 Novell Inc. (http://www.novell.com)
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

#if MONO_SECURITY_ALIAS
extern alias MonoSecurity;
using MonoSecurity::Mono.Security;
using MonoSecurity::Mono.Security.Cryptography;
using MX = MonoSecurity::Mono.Security.X509;
#else
using Mono.Security;
using Mono.Security.Cryptography;
using MX = Mono.Security.X509;
#endif

using System.IO;
using System.Text;
using System.Collections;
using System.Runtime.Serialization;
using Microsoft.Win32.SafeHandles;
using Internal.Cryptography;
using Mono;

namespace System.Security.Cryptography.X509Certificates
{
	[Serializable]
	public class X509Certificate2 : X509Certificate
	{
		volatile byte[] lazyRawData;
		volatile Oid lazySignatureAlgorithm;
		volatile int lazyVersion;
		volatile X500DistinguishedName lazySubjectName;
		volatile X500DistinguishedName lazyIssuerName;
		volatile PublicKey lazyPublicKey;
		volatile AsymmetricAlgorithm lazyPrivateKey;
		volatile X509ExtensionCollection lazyExtensions;

		public override void Reset ()
		{
			lazyRawData = null;
			lazySignatureAlgorithm = null;
			lazyVersion = 0;
			lazySubjectName = null;
			lazyIssuerName = null;
			lazyPublicKey = null;
			lazyPrivateKey = null;
			lazyExtensions = null;

			base.Reset ();
		}

		public X509Certificate2 ()
			: base ()
		{
		}

		public X509Certificate2 (byte[] rawData)
			: base (rawData)
		{
		}

		public X509Certificate2 (byte[] rawData, string password)
			: base (rawData, password)
		{
		}

		[System.CLSCompliantAttribute (false)]
		public X509Certificate2 (byte[] rawData, SecureString password)
			: base (rawData, password)
		{
		}

		public X509Certificate2 (byte[] rawData, string password, X509KeyStorageFlags keyStorageFlags)
			: base (rawData, password, keyStorageFlags)
		{
		}

		[System.CLSCompliantAttribute (false)]
		public X509Certificate2 (byte[] rawData, SecureString password, X509KeyStorageFlags keyStorageFlags)
			: base (rawData, password, keyStorageFlags)
		{
		}

		public X509Certificate2 (IntPtr handle)
			: base (handle)
		{
		}

		// CoreFX uses ICertificatePal here.
		internal X509Certificate2 (X509Certificate2Impl impl)
			: base (impl)
		{
		}

		public X509Certificate2 (string fileName)
			: base (fileName)
		{
		}

		public X509Certificate2 (string fileName, string password)
			: base (fileName, password)
		{
		}

		[System.CLSCompliantAttribute (false)]
		public X509Certificate2 (string fileName, SecureString password)
			: base (fileName, password)
		{
		}


		public X509Certificate2 (string fileName, string password, X509KeyStorageFlags keyStorageFlags)
			: base (fileName, password, keyStorageFlags)
		{
		}

		[System.CLSCompliantAttribute (false)]
		public X509Certificate2 (string fileName, SecureString password, X509KeyStorageFlags keyStorageFlags)
			: base (fileName, password, keyStorageFlags)
		{
		}

		public X509Certificate2 (X509Certificate certificate)
			: base (certificate)
		{
		}

		protected X509Certificate2 (SerializationInfo info, StreamingContext context)
			: base (info, context)
		{
			throw new PlatformNotSupportedException ();
		}

		public bool Archived {
			get {
				ThrowIfInvalid ();
				return Impl.Archived;
			}

			set {
				ThrowIfInvalid ();
				Impl.Archived = value;
			}
		}

		public X509ExtensionCollection Extensions {
			get {
				ThrowIfInvalid ();

				X509ExtensionCollection extensions = lazyExtensions;
				if (extensions == null) {
					extensions = new X509ExtensionCollection ();
					foreach (X509Extension extension in Impl.Extensions) {
						X509Extension customExtension = CreateCustomExtensionIfAny (extension.Oid);
						if (customExtension == null) {
							extensions.Add (extension);
						} else {
							customExtension.CopyFrom (extension);
							extensions.Add (customExtension);
						}
					}
					lazyExtensions = extensions;
				}
				return extensions;
			}
		}

		public string FriendlyName {
			get {
				ThrowIfInvalid ();
				return Impl.FriendlyName;
			}

			set {
				ThrowIfInvalid ();
				Impl.FriendlyName = value;
			}
		}

		public bool HasPrivateKey {
			get {
				ThrowIfInvalid ();
				return Impl.HasPrivateKey;
			}
		}

#region Mono Implementation

		public AsymmetricAlgorithm PrivateKey {
			get { return Impl.PrivateKey; }
			set { Impl.PrivateKey = value; }
		}

#endregion

		public X500DistinguishedName IssuerName {
			get {
				ThrowIfInvalid ();

				X500DistinguishedName issuerName = lazyIssuerName;
				if (issuerName == null)
					issuerName = lazyIssuerName = Impl.IssuerName;
				return issuerName;
			}
		}

		public DateTime NotAfter {
			get { return GetNotAfter (); }
		}

		public DateTime NotBefore {
			get { return GetNotBefore (); }
		}

		public PublicKey PublicKey {
			get {
				ThrowIfInvalid ();

				PublicKey publicKey = lazyPublicKey;
				if (publicKey == null) {
					string keyAlgorithmOid = GetKeyAlgorithm ();
					byte[] parameters = GetKeyAlgorithmParameters ();
					byte[] keyValue = GetPublicKey ();
					Oid oid = new Oid (keyAlgorithmOid);
					publicKey = lazyPublicKey = new PublicKey (oid, new AsnEncodedData (oid, parameters), new AsnEncodedData (oid, keyValue));
				}
				return publicKey;
			}
		}

		//
		// MARTIN CHECK POINT
		//


#if FIXME

		public X509Certificate2 ()
		{
		}

		public X509Certificate2 (byte[] rawData)
		{
			Import (rawData, (string)null, X509KeyStorageFlags.DefaultKeySet);
		}

		public X509Certificate2 (byte[] rawData, string password)
		{
			Import (rawData, password, X509KeyStorageFlags.DefaultKeySet);
		}

		public X509Certificate2 (byte[] rawData, SecureString password)
		{
			Import (rawData, password, X509KeyStorageFlags.DefaultKeySet);
		}

		public X509Certificate2 (byte[] rawData, string password, X509KeyStorageFlags keyStorageFlags)
		{
			Import (rawData, password, keyStorageFlags);
		}

		public X509Certificate2 (byte[] rawData, SecureString password, X509KeyStorageFlags keyStorageFlags)
		{
			Import (rawData, password, keyStorageFlags);
		}

		public X509Certificate2 (string fileName)
		{
			Import (fileName, String.Empty, X509KeyStorageFlags.DefaultKeySet);
		}

		public X509Certificate2 (string fileName, string password)
		{
			Import (fileName, password, X509KeyStorageFlags.DefaultKeySet);
		}

		public X509Certificate2 (string fileName, SecureString password)
		{
			Import (fileName, password, X509KeyStorageFlags.DefaultKeySet);
		}

		public X509Certificate2 (string fileName, string password, X509KeyStorageFlags keyStorageFlags)
		{
			Import (fileName, password, keyStorageFlags);
		}

		public X509Certificate2 (string fileName, SecureString password, X509KeyStorageFlags keyStorageFlags)
		{
			Import (fileName, password, keyStorageFlags);
		}

		public X509Certificate2 (IntPtr handle) : base (handle) 
		{
			throw new NotImplementedException ();
		}

		public X509Certificate2 (X509Certificate certificate) 
			: base (SystemDependencyProvider.Instance.CertificateProvider.Import (certificate))
		{
		}

		protected X509Certificate2 (SerializationInfo info, StreamingContext context) : base (info, context)
		{
		}

		internal X509Certificate2 (X509Certificate2Impl impl)
			: base (impl)
		{
		}

#endif


		new internal X509Certificate2Impl Impl {
			get {
				var impl2 = base.Impl as X509Certificate2Impl;
				X509Helper.ThrowIfContextInvalid (impl2);
				return impl2;
			}
		}

		// properties

		public byte[] RawData {
			get { return GetRawCertData (); }
		}

		public string SerialNumber {
			get { return GetSerialNumberString (); }
		} 

		public Oid SignatureAlgorithm {
			get {
				ThrowIfInvalid ();

				Oid signatureAlgorithm = lazySignatureAlgorithm;
				if (signatureAlgorithm == null) {
					string oidValue = Impl.SignatureAlgorithm;
					signatureAlgorithm = lazySignatureAlgorithm = Oid.FromOidValue (oidValue, OidGroup.SignatureAlgorithm);
				}
				return signatureAlgorithm;
			}
		} 

		public X500DistinguishedName SubjectName {
			get { return Impl.SubjectName; }
		} 

		public string Thumbprint {
			get { return GetCertHashString (); }
		} 

		public int Version {
			get { return Impl.Version; }
		}

		// methods

		[MonoTODO ("always return String.Empty for UpnName, DnsFromAlternativeName and UrlName")]
		public string GetNameInfo (X509NameType nameType, bool forIssuer) 
		{
			return Impl.GetNameInfo (nameType, forIssuer);
		}

		public override void Import (byte[] rawData) 
		{
			Import (rawData, (string)null, X509KeyStorageFlags.DefaultKeySet);
		}

		[MonoTODO ("missing KeyStorageFlags support")]
		public override void Import (byte[] rawData, string password, X509KeyStorageFlags keyStorageFlags)
		{
			Reset ();
			using (var handle = new SafePasswordHandle (password)) {
				var impl = SystemDependencyProvider.Instance.CertificateProvider.Import (rawData, handle, keyStorageFlags);
				ImportHandle (impl);
			}
		}

		public override void Import (byte[] rawData, SecureString password, X509KeyStorageFlags keyStorageFlags)
		{
			Reset ();
			using (var handle = new SafePasswordHandle (password)) {
				var impl = SystemDependencyProvider.Instance.CertificateProvider.Import (rawData, handle, keyStorageFlags);
				ImportHandle (impl);
			}
		}

		public override void Import (string fileName) 
		{
			byte[] rawData = File.ReadAllBytes (fileName);
			Import (rawData, (string)null, X509KeyStorageFlags.DefaultKeySet);
		}

		[MonoTODO ("missing KeyStorageFlags support")]
		public override void Import (string fileName, string password, X509KeyStorageFlags keyStorageFlags) 
		{
			byte[] rawData = File.ReadAllBytes (fileName);
			Import (rawData, password, keyStorageFlags);
		}

		[MonoTODO ("SecureString is incomplete")]
		public override void Import (string fileName, SecureString password, X509KeyStorageFlags keyStorageFlags) 
		{
			byte[] rawData = File.ReadAllBytes (fileName);
			Import (rawData, password, keyStorageFlags);
		}

		[MonoTODO ("X509ContentType.SerializedCert is not supported")]
		public override byte[] Export (X509ContentType contentType, string password)
		{
			X509Helper.ThrowIfContextInvalid (Impl);
			using (var handle = new SafePasswordHandle (password)) {
				return Impl.Export (contentType, handle);
			}
		}

		public override string ToString ()
		{
			if (!IsValid)
				return "System.Security.Cryptography.X509Certificates.X509Certificate2";
			return base.ToString (true);
		}

		public override string ToString (bool verbose)
		{
			if (!IsValid)
				return "System.Security.Cryptography.X509Certificates.X509Certificate2";

			// the non-verbose X509Certificate2 == verbose X509Certificate
			if (!verbose)
				return base.ToString (true);

			string nl = Environment.NewLine;
			StringBuilder sb = new StringBuilder ();
			sb.AppendFormat ("[Version]{0}  V{1}{0}{0}", nl, Version);
			sb.AppendFormat ("[Subject]{0}  {1}{0}{0}", nl, Subject);
			sb.AppendFormat ("[Issuer]{0}  {1}{0}{0}", nl, Issuer);
			sb.AppendFormat ("[Serial Number]{0}  {1}{0}{0}", nl, SerialNumber);
			sb.AppendFormat ("[Not Before]{0}  {1}{0}{0}", nl, NotBefore);
			sb.AppendFormat ("[Not After]{0}  {1}{0}{0}", nl, NotAfter);
			sb.AppendFormat ("[Thumbprint]{0}  {1}{0}{0}", nl, Thumbprint);
			sb.AppendFormat ("[Signature Algorithm]{0}  {1}({2}){0}{0}", nl, SignatureAlgorithm.FriendlyName, 
				SignatureAlgorithm.Value);

			AsymmetricAlgorithm key = PublicKey.Key;
			sb.AppendFormat ("[Public Key]{0}  Algorithm: ", nl);
			if (key is RSA)
				sb.Append ("RSA");
			else if (key is DSA)
				sb.Append ("DSA");
			else
				sb.Append (key.ToString ());
			sb.AppendFormat ("{0}  Length: {1}{0}  Key Blob: ", nl, key.KeySize);
			AppendBuffer (sb, PublicKey.EncodedKeyValue.RawData);
			sb.AppendFormat ("{0}  Parameters: ", nl);
			AppendBuffer (sb, PublicKey.EncodedParameters.RawData);
			sb.Append (nl);

			return sb.ToString ();
		}

		private static void AppendBuffer (StringBuilder sb, byte[] buffer)
		{
			if (buffer == null)
				return;
			for (int i=0; i < buffer.Length; i++) {
				sb.Append (buffer [i].ToString ("x2"));
				if (i < buffer.Length - 1)
					sb.Append (" ");
			}
		}

		[MonoTODO ("by default this depends on the incomplete X509Chain")]
		public bool Verify ()
		{
			return Impl.Verify (this);
		}

		// static methods

		private static byte[] signedData = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02 };

		[MonoTODO ("Detection limited to Cert, Pfx/Pkcs12, Pkcs7 and Unknown")]
		public static X509ContentType GetCertContentType (byte[] rawData)
		{
			if ((rawData == null) || (rawData.Length == 0))
				throw new ArgumentException ("rawData");

			if (rawData[0] == 0x30) {
				// ASN.1 SEQUENCE
				try {
					ASN1 data = new ASN1 (rawData);

					// SEQUENCE / SEQUENCE / BITSTRING
					if (data.Count == 3 && data [0].Tag == 0x30 && data [1].Tag == 0x30 && data [2].Tag == 0x03)
						return X509ContentType.Cert;

					// INTEGER / SEQUENCE / SEQUENCE
					if (data.Count == 3 && data [0].Tag == 0x02 && data [1].Tag == 0x30 && data [2].Tag == 0x30)
						return X509ContentType.Pkcs12; // note: Pfx == Pkcs12

					// check for PKCS#7 (count unknown but greater than 0)
					// SEQUENCE / OID (signedData)
					if (data.Count > 0 && data [0].Tag == 0x06 && data [0].CompareValue (signedData))
						return X509ContentType.Pkcs7;
					
					return X509ContentType.Unknown;
				}
				catch (Exception) {
					return X509ContentType.Unknown;
				}
			} else {
				string pem = Encoding.ASCII.GetString (rawData);
				int start = pem.IndexOf ("-----BEGIN CERTIFICATE-----");
				if (start >= 0)
					return X509ContentType.Cert;
			}

			return X509ContentType.Unknown;
		}

		[MonoTODO ("Detection limited to Cert, Pfx, Pkcs12 and Unknown")]
		public static X509ContentType GetCertContentType (string fileName)
		{
			if (fileName == null)
				throw new ArgumentNullException ("fileName");
			if (fileName.Length == 0)
				throw new ArgumentException ("fileName");

			byte[] data = File.ReadAllBytes (fileName);
			return GetCertContentType (data);
		}

		// internal stuff because X509Certificate2 isn't complete enough
		// (maybe X509Certificate3 will be better?)

		[MonoTODO ("See comment in X509Helper2.GetMonoCertificate().")]
		internal MX.X509Certificate MonoCertificate {
			get {
				return X509Helper2.GetMonoCertificate (this);
			}
		}

		static X509Extension CreateCustomExtensionIfAny (Oid oid)
		{
			string oidValue = oid.Value;
			switch (oidValue) {
			case Oids.BasicConstraints:
#if FIXME
				return X509Pal.Instance.SupportsLegacyBasicConstraintsExtension ?
				    new X509BasicConstraintsExtension () :
				    null;
#else
				return null;
#endif

			case Oids.BasicConstraints2:
				return new X509BasicConstraintsExtension ();

			case Oids.KeyUsage:
				return new X509KeyUsageExtension ();

			case Oids.EnhancedKeyUsage:
				return new X509EnhancedKeyUsageExtension ();

			case Oids.SubjectKeyIdentifier:
				return new X509SubjectKeyIdentifierExtension ();

			default:
				return null;
			}
		}

	}
}
