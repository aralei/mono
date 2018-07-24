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

		public byte[] RawData {
			get {
				ThrowIfInvalid ();

				byte[] rawData = lazyRawData;
				if (rawData == null)
					rawData = lazyRawData = Impl.RawData;
				return rawData.CloneByteArray ();
			}
		}

		public string SerialNumber {
			get {
				return GetSerialNumberString ();
			}
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
			get {
				ThrowIfInvalid ();

				X500DistinguishedName subjectName = lazySubjectName;
				if (subjectName == null)
					subjectName = lazySubjectName = Impl.SubjectName;
				return subjectName;
			}
		}

		public string Thumbprint {
			get {
				byte[] thumbPrint = GetCertHash ();
				return thumbPrint.ToHexStringUpper ();
			}
		}

		public int Version {
			get {
				ThrowIfInvalid ();

				int version = lazyVersion;
				if (version == 0)
					version = lazyVersion = Impl.Version;
				return version;
			}
		}

		#region Martin Check Point

		/*
		 * GetCertContentType()
		 *
		 * public static X509ContentType GetCertContentType(byte[] rawData)
		 * public static X509ContentType GetCertContentType(string fileName)
		 *
		 */

		#endregion

		public string GetNameInfo (X509NameType nameType, bool forIssuer)
		{
			return Impl.GetNameInfo (nameType, forIssuer);
		}

		public override string ToString ()
		{
			return base.ToString (fVerbose: true);
		}

		public override string ToString (bool verbose)
		{
			if (verbose == false || !IsValid)
				return ToString ();

			StringBuilder sb = new StringBuilder ();

			// Version
			sb.AppendLine ("[Version]");
			sb.Append ("  V");
			sb.Append (Version);

			// Subject
			sb.AppendLine ();
			sb.AppendLine ();
			sb.AppendLine ("[Subject]");
			sb.Append ("  ");
			sb.Append (SubjectName.Name);
			string simpleName = GetNameInfo (X509NameType.SimpleName, false);
			if (simpleName.Length > 0) {
				sb.AppendLine ();
				sb.Append ("  ");
				sb.Append ("Simple Name: ");
				sb.Append (simpleName);
			}
			string emailName = GetNameInfo (X509NameType.EmailName, false);
			if (emailName.Length > 0) {
				sb.AppendLine ();
				sb.Append ("  ");
				sb.Append ("Email Name: ");
				sb.Append (emailName);
			}
			string upnName = GetNameInfo (X509NameType.UpnName, false);
			if (upnName.Length > 0) {
				sb.AppendLine ();
				sb.Append ("  ");
				sb.Append ("UPN Name: ");
				sb.Append (upnName);
			}
			string dnsName = GetNameInfo (X509NameType.DnsName, false);
			if (dnsName.Length > 0) {
				sb.AppendLine ();
				sb.Append ("  ");
				sb.Append ("DNS Name: ");
				sb.Append (dnsName);
			}

			// Issuer
			sb.AppendLine ();
			sb.AppendLine ();
			sb.AppendLine ("[Issuer]");
			sb.Append ("  ");
			sb.Append (IssuerName.Name);
			simpleName = GetNameInfo (X509NameType.SimpleName, true);
			if (simpleName.Length > 0) {
				sb.AppendLine ();
				sb.Append ("  ");
				sb.Append ("Simple Name: ");
				sb.Append (simpleName);
			}
			emailName = GetNameInfo (X509NameType.EmailName, true);
			if (emailName.Length > 0) {
				sb.AppendLine ();
				sb.Append ("  ");
				sb.Append ("Email Name: ");
				sb.Append (emailName);
			}
			upnName = GetNameInfo (X509NameType.UpnName, true);
			if (upnName.Length > 0) {
				sb.AppendLine ();
				sb.Append ("  ");
				sb.Append ("UPN Name: ");
				sb.Append (upnName);
			}
			dnsName = GetNameInfo (X509NameType.DnsName, true);
			if (dnsName.Length > 0) {
				sb.AppendLine ();
				sb.Append ("  ");
				sb.Append ("DNS Name: ");
				sb.Append (dnsName);
			}

			// Serial Number
			sb.AppendLine ();
			sb.AppendLine ();
			sb.AppendLine ("[Serial Number]");
			sb.Append ("  ");
			sb.AppendLine (SerialNumber);

			// NotBefore
			sb.AppendLine ();
			sb.AppendLine ("[Not Before]");
			sb.Append ("  ");
			sb.AppendLine (FormatDate (NotBefore));

			// NotAfter
			sb.AppendLine ();
			sb.AppendLine ("[Not After]");
			sb.Append ("  ");
			sb.AppendLine (FormatDate (NotAfter));

			// Thumbprint
			sb.AppendLine ();
			sb.AppendLine ("[Thumbprint]");
			sb.Append ("  ");
			sb.AppendLine (Thumbprint);

			// Signature Algorithm
			sb.AppendLine ();
			sb.AppendLine ("[Signature Algorithm]");
			sb.Append ("  ");
			sb.Append (SignatureAlgorithm.FriendlyName);
			sb.Append ('(');
			sb.Append (SignatureAlgorithm.Value);
			sb.AppendLine (")");

			// Public Key
			sb.AppendLine ();
			sb.Append ("[Public Key]");
			// It could throw if it's some user-defined CryptoServiceProvider
			try {
				PublicKey pubKey = PublicKey;

				sb.AppendLine ();
				sb.Append ("  ");
				sb.Append ("Algorithm: ");
				sb.Append (pubKey.Oid.FriendlyName);
				// So far, we only support RSACryptoServiceProvider & DSACryptoServiceProvider Keys
				try {
					sb.AppendLine ();
					sb.Append ("  ");
					sb.Append ("Length: ");

					using (RSA pubRsa = this.GetRSAPublicKey ()) {
						if (pubRsa != null) {
							sb.Append (pubRsa.KeySize);
						}
					}
				} catch (NotSupportedException) {
				}

				sb.AppendLine ();
				sb.Append ("  ");
				sb.Append ("Key Blob: ");
				sb.AppendLine (pubKey.EncodedKeyValue.Format (true));

				sb.Append ("  ");
				sb.Append ("Parameters: ");
				sb.Append (pubKey.EncodedParameters.Format (true));
			} catch (CryptographicException) {
			}

			// Private key
			Impl.AppendPrivateKeyInfo (sb);

			// Extensions
			X509ExtensionCollection extensions = Extensions;
			if (extensions.Count > 0) {
				sb.AppendLine ();
				sb.AppendLine ();
				sb.Append ("[Extensions]");
				foreach (X509Extension extension in extensions) {
					try {
						sb.AppendLine ();
						sb.Append ("* ");
						sb.Append (extension.Oid.FriendlyName);
						sb.Append ('(');
						sb.Append (extension.Oid.Value);
						sb.Append ("):");

						sb.AppendLine ();
						sb.Append ("  ");
						sb.Append (extension.Format (true));
					} catch (CryptographicException) {
					}
				}
			}

			sb.AppendLine ();
			return sb.ToString ();
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

		// methods

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
