using Minisign.Exceptions;
using Minisign.Helper;
using Minisign.Models;
using Sodium;
using System;
using System.IO;
using System.Linq;
using System.Security;
using System.Text;

namespace Minisign
{
	/// <summary>
	///     Main class to handle minisign files and objects.
	/// </summary>
	public static class Core
	{
		private const long MaxMessageFileSize = 1024000000;
		private const int CommentMaxBytes = 1024;
		private const int TrustedCommentMaxBytes = 8192;
		private const int KeyNumBytes = 8;
		private const int KeySaltBytes = 32;
		private const string Sigalg = "Ed";
		private const string Kdfalg = "Sc";
		private const string Chkalg = "B2";
		private const string DefaultComment = "signature from minisign secret key";
		private const string CommentPrefix = "untrusted comment: ";
		private const string TrustedCommentPrefix = "trusted comment: ";
		private const string PrivateKeyDefaultComment = "minisign encrypted secret key";
		private const string SigSuffix = ".minisig";
		private const string PrivateKeyFileSuffix = ".key";
		private const string PublicKeyFileSuffix = ".pub";

		#region Main Functions

		/// <summary>
		///     Sign a file with a MinisignPrivateKey.
		/// </summary>
		/// <param name="fileToSign">The full path to the file.</param>
		/// <param name="minisignPrivateKey">A valid MinisignPrivateKey to sign.</param>
		/// <param name="untrustedComment">An optional untrusted comment.</param>
		/// <param name="trustedComment">An optional trusted comment.</param>
		/// <param name="outputFolder">The folder to write the signature (optional).</param>
		/// <returns>The full path to the signed file.</returns>
		/// <exception cref="FileNotFoundException"></exception>
		/// <exception cref="ArgumentException"></exception>
		/// <exception cref="ArgumentOutOfRangeException"></exception>
		/// <exception cref="OverflowException"></exception>
		/// <exception cref="DirectoryNotFoundException"></exception>
		/// <exception cref="IOException"></exception>
		/// <exception cref="UnauthorizedAccessException"></exception>
		/// <exception cref="SecurityException"></exception>
		/// <exception cref="ArgumentNullException"></exception>
		/// <exception cref="PathTooLongException"></exception>
		/// <exception cref="NotSupportedException"></exception>
		public static string Sign(string fileToSign, MinisignPrivateKey minisignPrivateKey, string untrustedComment = "",
			string trustedComment = "", string outputFolder = "")
		{
			if (fileToSign != null && !File.Exists(fileToSign))
			{
				throw new FileNotFoundException("could not find fileToSign");
			}

			if (minisignPrivateKey == null)
				throw new ArgumentException("missing minisignPrivateKey input", nameof(minisignPrivateKey));

			if (string.IsNullOrEmpty(untrustedComment))
			{
				untrustedComment = DefaultComment;
			}

			if (string.IsNullOrEmpty(trustedComment))
			{
				var timestamp = GetTimestamp();
				var filename = Path.GetFileName(fileToSign);
				trustedComment = "timestamp: " + timestamp + " file: " + filename;
			}

			if ((CommentPrefix + untrustedComment).Length > CommentMaxBytes)
			{
				throw new ArgumentOutOfRangeException(nameof(untrustedComment), "untrustedComment too long");
			}

			if ((TrustedCommentPrefix + trustedComment).Length > TrustedCommentMaxBytes)
			{
				throw new ArgumentOutOfRangeException(nameof(trustedComment), "trustedComment too long");
			}

			if (string.IsNullOrEmpty(outputFolder))
			{
				outputFolder = Path.GetDirectoryName(fileToSign);
			}

			//validate the outputFolder
			if (string.IsNullOrEmpty(outputFolder) || !Directory.Exists(outputFolder))
			{
				throw new DirectoryNotFoundException("outputFolder must exist");
			}

			if (outputFolder.IndexOfAny(Path.GetInvalidPathChars()) > -1)
				throw new ArgumentException("The given path to the output folder contains invalid characters!");

			var file = LoadMessageFile(fileToSign);

			var minisignSignature = new MinisignSignature
			{
				KeyId = minisignPrivateKey.KeyId,
				SignatureAlgorithm = Encoding.UTF8.GetBytes(Sigalg)
			};
			var signature = PublicKeyAuth.SignDetached(file, minisignPrivateKey.SecretKey);
			minisignSignature.Signature = signature;

			var binarySignature = ArrayHelpers.ConcatArrays(
				minisignSignature.SignatureAlgorithm,
				minisignSignature.KeyId,
				minisignSignature.Signature
				);

			// sign the signature and the trusted comment with a global signature
			var globalSignature =
				PublicKeyAuth.SignDetached(
					ArrayHelpers.ConcatArrays(minisignSignature.Signature, Encoding.UTF8.GetBytes(trustedComment)),
					minisignPrivateKey.SecretKey);

			// prepare the file lines
			var signatureFileContent = new[]
			{
				CommentPrefix + untrustedComment,
				Convert.ToBase64String(binarySignature),
				TrustedCommentPrefix + trustedComment,
				Convert.ToBase64String(globalSignature)
			};

			var outputFile = fileToSign + SigSuffix;
			File.WriteAllLines(outputFile, signatureFileContent);
			return outputFile;
		}

		/// <summary>
		///     Generate a new Minisign key pair.
		/// </summary>
		/// <param name="password">The password to protect the secret key.</param>
		/// <param name="writeOutputFiles">If false, no files will be written.</param>
		/// <param name="outputFolder">The folder to write the files (optional).</param>
		/// <param name="keyPairFileName">The name of the files to write (optional).</param>
		/// <returns>A MinisignKeyPair object.</returns>
		/// <exception cref="ArgumentException"></exception>
		/// <exception cref="OverflowException"></exception>
		/// <exception cref="DirectoryNotFoundException"></exception>
		/// <exception cref="ArgumentNullException"></exception>
		/// <exception cref="IOException"></exception>
		/// <exception cref="UnauthorizedAccessException"></exception>
		/// <exception cref="PathTooLongException"></exception>
		/// <exception cref="SecurityException"></exception>
		/// <exception cref="NotSupportedException"></exception>
		/// <exception cref="ArgumentOutOfRangeException"></exception>
		public static MinisignKeyPair GenerateKeyPair(string password, bool writeOutputFiles = false,
			string outputFolder = "", string keyPairFileName = "minisign")
		{
			if (string.IsNullOrEmpty(password))
			{
				throw new ArgumentNullException(nameof(password), "password can not be null");
			}

			if (writeOutputFiles)
			{
				//validate the outputFolder
				if (string.IsNullOrEmpty(outputFolder) || !Directory.Exists(outputFolder))
				{
					throw new DirectoryNotFoundException("outputFolder must exist");
				}

				if (outputFolder.IndexOfAny(Path.GetInvalidPathChars()) > -1)
					throw new ArgumentException("The given path to the output folder contains invalid characters!");

				//validate the keyPairFileName
				if (string.IsNullOrEmpty(keyPairFileName))
				{
					throw new ArgumentNullException(nameof(keyPairFileName), "keyPairFileName can not be empty");
				}
			}

			var minisignKeyPair = new MinisignKeyPair();
			var minisignPrivateKey = new MinisignPrivateKey();
			var keyPair = PublicKeyAuth.GenerateKeyPair();
			var keyId = SodiumCore.GetRandomBytes(KeyNumBytes);
			var kdfSalt = SodiumCore.GetRandomBytes(32);

			minisignPrivateKey.PublicKey = keyPair.PublicKey;
			minisignPrivateKey.KdfSalt = kdfSalt;
			minisignPrivateKey.SignatureAlgorithm = Encoding.UTF8.GetBytes(Sigalg);
			minisignPrivateKey.ChecksumAlgorithm = Encoding.UTF8.GetBytes(Chkalg);
			minisignPrivateKey.KdfAlgorithm = Encoding.UTF8.GetBytes(Kdfalg);
			minisignPrivateKey.KdfMemLimit = 1073741824; //currently unused
			minisignPrivateKey.KdfOpsLimit = 33554432; //currently unused

			var checksum =
				GenericHash.Hash(
					ArrayHelpers.ConcatArrays(minisignPrivateKey.SignatureAlgorithm, keyId, keyPair.PrivateKey), null,
					32);
			minisignPrivateKey.KeyId = keyId;
			minisignPrivateKey.SecretKey = keyPair.PrivateKey;
			minisignPrivateKey.Checksum = checksum;

			var dataToProtect = ArrayHelpers.ConcatArrays(keyId, keyPair.PrivateKey, checksum);
			var encryptionKey = PasswordHash.ScryptHashBinary(Encoding.UTF8.GetBytes(password),
				minisignPrivateKey.KdfSalt,
				PasswordHash.Strength.Sensitive,
				104);

			var encryptedKeyData = EncryptionHelpers.Xor(dataToProtect, encryptionKey);
			// set up the public key
			var minisignPublicKey = new MinisignPublicKey
			{
				KeyId = keyId,
				PublicKey = keyPair.PublicKey,
				SignatureAlgorithm = Encoding.UTF8.GetBytes(Sigalg)
			};
			keyPair.Dispose();
			if (writeOutputFiles)
			{
				var privateKeyOutputFileName = Path.Combine(outputFolder, keyPairFileName + PrivateKeyFileSuffix);
				var publicKeyOutputFileName = Path.Combine(outputFolder, keyPairFileName + PublicKeyFileSuffix);

				var binaryPublicKey = ArrayHelpers.ConcatArrays(
					minisignPublicKey.SignatureAlgorithm,
					minisignPublicKey.KeyId,
					minisignPublicKey.PublicKey
					);

				var publicFileContent = new[]
				{
					CommentPrefix + "minisign public key " +
					Utilities.BinaryToHex(minisignPublicKey.KeyId, Utilities.HexFormat.None, Utilities.HexCase.Upper),
					Convert.ToBase64String(binaryPublicKey)
				};

				var binaryPrivateKey = ArrayHelpers.ConcatArrays(
					minisignPrivateKey.SignatureAlgorithm,
					minisignPrivateKey.KdfAlgorithm,
					minisignPrivateKey.ChecksumAlgorithm,
					minisignPrivateKey.KdfSalt,
					BitConverter.GetBytes(minisignPrivateKey.KdfOpsLimit),
					BitConverter.GetBytes(minisignPrivateKey.KdfMemLimit),
					encryptedKeyData
					);

				var privateFileContent = new[]
				{
					CommentPrefix + PrivateKeyDefaultComment,
					Convert.ToBase64String(binaryPrivateKey)
				};
				// files will be overwritten!
				File.WriteAllLines(publicKeyOutputFileName, publicFileContent);
				File.WriteAllLines(privateKeyOutputFileName, privateFileContent);

				minisignKeyPair.MinisignPublicKeyFilePath = publicKeyOutputFileName;
				minisignKeyPair.MinisignPrivateKeyFilePath = privateKeyOutputFileName;
			}

			minisignKeyPair.MinisignPublicKey = minisignPublicKey;
			minisignKeyPair.MinisignPrivateKey = minisignPrivateKey;
			return minisignKeyPair;
		}

		/// <summary>
		///     Validate a file with a MinisignSignature and a MinisignPublicKey object.
		/// </summary>
		/// <param name="filePath">The full path to the file.</param>
		/// <param name="signature">A valid MinisignSignature object.</param>
		/// <param name="publicKey">A valid MinisignPublicKey object.</param>
		/// <returns><c>true</c> if valid; otherwise, <c>false</c>.</returns>
		/// <exception cref="FileNotFoundException"></exception>
		/// <exception cref="OverflowException"></exception>
		/// <exception cref="ArgumentNullException"></exception>
		/// <exception cref="ArgumentException"></exception>
		/// <exception cref="ArgumentOutOfRangeException"></exception>
		public static bool ValidateSignature(string filePath, MinisignSignature signature, MinisignPublicKey publicKey)
		{
			if (filePath != null && !File.Exists(filePath))
				throw new FileNotFoundException("could not find filePath");

			if (signature == null)
				throw new ArgumentException("missing signature input", nameof(signature));

			if (publicKey == null)
				throw new ArgumentException("missing publicKey input", nameof(publicKey));

			if (!ArrayHelpers.ConstantTimeEquals(signature.KeyId, publicKey.KeyId)) return false;


			if (!signature.IsHashed)
			{
				var file = LoadMessageFile(filePath);

				// Legacy: Ed25519(message)
				if (!PublicKeyAuth.VerifyDetached(signature.Signature, file, publicKey.PublicKey)) return false;
			}
			else
			{
				// Hashed: Ed25519(Blake2b-512(message))
				var blake = ComputeBlake2bFileHash(filePath);
				if (!PublicKeyAuth.VerifyDetached(signature.Signature, blake, publicKey.PublicKey)) return false;
			}

			// Global signature is the same for both formats
			return PublicKeyAuth.VerifyDetached(
				signature.GlobalSignature,
				ArrayHelpers.ConcatArrays(signature.Signature, signature.TrustedComment),
				publicKey.PublicKey);
		}


		/// <summary>
		///     Validate a file with a MinisignSignature and a MinisignPublicKey object.
		/// </summary>
		/// <param name="message">The message to validate.</param>
		/// <param name="signature">A valid MinisignSignature object.</param>
		/// <param name="publicKey">A valid MinisignPublicKey object.</param>
		/// <returns><c>true</c> if valid; otherwise, <c>false</c>.</returns>
		/// <exception cref="OverflowException"></exception>
		/// <exception cref="ArgumentNullException"></exception>
		/// <exception cref="ArgumentException"></exception>
		/// <exception cref="ArgumentOutOfRangeException"></exception>
		public static bool ValidateSignature(byte[] message, MinisignSignature signature, MinisignPublicKey publicKey)
		{
			if (message == null)
				throw new ArgumentException("missing signature input", nameof(message));

			if (signature == null)
				throw new ArgumentException("missing signature input", nameof(signature));

			if (publicKey == null)
				throw new ArgumentException("missing publicKey input", nameof(publicKey));

			if (!ArrayHelpers.ConstantTimeEquals(signature.KeyId, publicKey.KeyId)) return false;

			if (!signature.IsHashed)
			{
				// Legacy: Ed25519(message)
				if (!PublicKeyAuth.VerifyDetached(signature.Signature, message, publicKey.PublicKey)) return false;
			}
			else
			{
				// Hashed: Ed25519(Blake2b-512(message))
				var blake = GenericHash.Hash(message, null, 64);
				if (!PublicKeyAuth.VerifyDetached(signature.Signature, blake, publicKey.PublicKey)) return false;
			}

			return PublicKeyAuth.VerifyDetached(
				signature.GlobalSignature,
				ArrayHelpers.ConcatArrays(signature.Signature, signature.TrustedComment),
				publicKey.PublicKey);
		}



		#endregion

		#region Signature Handling

		/// <summary>
		///     Load a signature from strings into a MinisignSignature object.
		/// </summary>
		/// <param name="signatureString">A valid base64 signature string.</param>
		/// <param name="trustedComment">The associated trusted comment.</param>
		/// <param name="globalSignature">The associated base64 global signature string.</param>
		/// <returns>A MinisignSignature object.</returns>
		/// <exception cref="ArgumentException"></exception>
		/// <exception cref="OverflowException"></exception>
		/// <exception cref="ArgumentOutOfRangeException"></exception>
		/// <exception cref="ArgumentNullException"></exception>
		public static MinisignSignature LoadSignatureFromString(string signatureString, string trustedComment,
			string globalSignature)
		{
			if (string.IsNullOrEmpty(signatureString))
				throw new ArgumentException("signatureString can not be null", nameof(signatureString));

			if (string.IsNullOrEmpty(trustedComment))
				throw new ArgumentException("trustedComment can not be null", nameof(trustedComment));

			if (string.IsNullOrEmpty(globalSignature))
				throw new ArgumentException("globalSignature can not be null", nameof(globalSignature));

			return LoadSignature(Convert.FromBase64String(signatureString), Encoding.UTF8.GetBytes(trustedComment),
				Convert.FromBase64String(globalSignature));
		}

		/// <summary>
		///     Load a signature from a file into a MinisignSignature object.
		/// </summary>
		/// <param name="signatureFile">The full path to the signature file.</param>
		/// <returns>A MinisignSignature object.</returns>
		/// <exception cref="FileNotFoundException"></exception>
		/// <exception cref="CorruptSignatureException"></exception>
		/// <exception cref="ArgumentNullException"></exception>
		/// <exception cref="DirectoryNotFoundException"></exception>
		/// <exception cref="IOException"></exception>
		/// <exception cref="SecurityException"></exception>
		/// <exception cref="UnauthorizedAccessException"></exception>
		/// <exception cref="PathTooLongException"></exception>
		/// <exception cref="ArgumentException"></exception>
		/// <exception cref="ArgumentOutOfRangeException"></exception>
		/// <exception cref="OverflowException"></exception>
		public static MinisignSignature LoadSignatureFromFile(string signatureFile)
		{
			if (signatureFile != null && !File.Exists(signatureFile))
			{
				throw new FileNotFoundException("could not find signatureFile");
			}

			var signatureLines = File.ReadLines(signatureFile).Take(4).ToList();
			if (signatureLines.Count != 4)
			{
				throw new CorruptSignatureException("the signature file has missing lines");
			}

			// do some simple pre-validation
			if (!signatureLines[0].StartsWith(CommentPrefix) &&
				!signatureLines[2].StartsWith(TrustedCommentPrefix))
			{
				throw new CorruptSignatureException("the signature file has invalid lines");
			}
			var trimmedComment = signatureLines[2].Replace(TrustedCommentPrefix, "").Trim();
			var trustedCommentBinary = Encoding.UTF8.GetBytes(trimmedComment);
			return LoadSignature(Convert.FromBase64String(signatureLines[1].Trim()), trustedCommentBinary,
				Convert.FromBase64String(signatureLines[3].Trim()));
		}

		/// <summary>
		///     Load a signature into a MinisignSignature object.
		/// </summary>
		/// <param name="signature">A valid signature.</param>
		/// <param name="trustedComment">The associated trustedComment.</param>
		/// <param name="globalSignature">The associated globalSignature.</param>
		/// <returns>A MinisignSignature object.</returns>
		/// <exception cref="OverflowException"></exception>
		/// <exception cref="ArgumentNullException"></exception>
		/// <exception cref="ArgumentException"></exception>
		/// <exception cref="ArgumentOutOfRangeException"></exception>
		public static MinisignSignature LoadSignature(byte[] signature, byte[] trustedComment, byte[] globalSignature)
		{
			if (signature == null)
				throw new ArgumentException("missing signature input", nameof(signature));

			if (trustedComment == null)
				throw new ArgumentException("missing trustedComment input", nameof(trustedComment));

			if (globalSignature == null)
				throw new ArgumentException("missing globalSignature input", nameof(globalSignature));

			var result = new MinisignSignature()
			{
				SignatureAlgorithm = ArrayHelpers.SubArray(signature, 0, 2),
				KeyId = ArrayHelpers.SubArray(signature, 2, 8),
				TrustedComment = trustedComment,
				GlobalSignature = globalSignature
			};

			var alg = Encoding.UTF8.GetString(result.SignatureAlgorithm);
				result.IsHashed = alg == "ED";

			if (!result.IsHashed)
			{
				// Legacy minisign: Ed + keyid(8) + raw signature
				result.Signature = ArrayHelpers.SubArray(signature, 10);
			}
			else
			{
				// Hashed minisign: ED + keyid(8) + signature(64)
				result.Signature = ArrayHelpers.SubArray(signature, 10, 64);
			}

			return result;
		}

		#endregion

		#region Public Key Handling

		/// <summary>
		///     Load a public key from a string into a MinisignPublicKey object.
		/// </summary>
		/// <param name="publicKeyString">A valid base64 public key string.</param>
		/// <returns>A MinisignPublicKey object.</returns>
		/// <exception cref="ArgumentException"></exception>
		/// <exception cref="OverflowException"></exception>
		/// <exception cref="ArgumentOutOfRangeException"></exception>
		/// <exception cref="ArgumentNullException"></exception>
		public static MinisignPublicKey LoadPublicKeyFromString(string publicKeyString)
		{
			if (string.IsNullOrEmpty(publicKeyString))
				throw new ArgumentException("publicKeyString can not be null", nameof(publicKeyString));

			return LoadPublicKey(Convert.FromBase64String(publicKeyString));
		}

		/// <summary>
		///     Load a public key from a file into a MinisignPublicKey object.
		/// </summary>
		/// <param name="publicKeyFile">The full path to the public key file.</param>
		/// <returns>A MinisignPublicKey object.</returns>
		/// <exception cref="FileNotFoundException"></exception>
		/// <exception cref="CorruptPublicKeyException"></exception>
		/// <exception cref="ArgumentOutOfRangeException"></exception>
		/// <exception cref="OverflowException"></exception>
		/// <exception cref="ArgumentNullException"></exception>
		/// <exception cref="ArgumentException"></exception>
		/// <exception cref="DirectoryNotFoundException"></exception>
		/// <exception cref="IOException"></exception>
		/// <exception cref="SecurityException"></exception>
		/// <exception cref="UnauthorizedAccessException"></exception>
		/// <exception cref="PathTooLongException"></exception>
		public static MinisignPublicKey LoadPublicKeyFromFile(string publicKeyFile)
		{
			if (publicKeyFile != null && !File.Exists(publicKeyFile))
			{
				throw new FileNotFoundException("could not find publicKeyFile");
			}

			var publicKeyLines = File.ReadLines(publicKeyFile).Take(2).ToList();
			if (publicKeyLines.Count != 2)
			{
				throw new CorruptPublicKeyException("the public key file has missing lines");
			}

			// do some simple pre-validation
			if (!publicKeyLines[0].StartsWith(CommentPrefix))
			{
				throw new CorruptPublicKeyException("the public key file has invalid lines");
			}

			return LoadPublicKey(Convert.FromBase64String(publicKeyLines[1]));
		}

		/// <summary>
		///     Load a public key into a MinisignPublicKey object.
		/// </summary>
		/// <param name="publicKey">A valid public key.</param>
		/// <returns>A MinisignPublicKey object.</returns>
		/// <exception cref="ArgumentException"></exception>
		/// <exception cref="OverflowException"></exception>
		/// <exception cref="ArgumentNullException"></exception>
		/// <exception cref="ArgumentOutOfRangeException"></exception>
		public static MinisignPublicKey LoadPublicKey(byte[] publicKey)
		{
			if (publicKey == null)
				throw new ArgumentException("missing publicKey input", nameof(publicKey));

			var minisignPublicKey = new MinisignPublicKey
			{
				SignatureAlgorithm = ArrayHelpers.SubArray(publicKey, 0, 2),
				KeyId = ArrayHelpers.SubArray(publicKey, 2, 8),
				PublicKey = ArrayHelpers.SubArray(publicKey, 10)
			};

			return minisignPublicKey;
		}

		#endregion

		#region Private Key Handling

		/// <summary>
		///     Load a private key from a string into a MinisignPrivateKey object.
		/// </summary>
		/// <param name="privateKeyString">A valid Base64 string.</param>
		/// <param name="password">The password to decrypt the private key.</param>
		/// <returns>A MinisignPrivateKey object.</returns>
		/// <exception cref="OverflowException"></exception>
		/// <exception cref="ArgumentException"></exception>
		/// <exception cref="CorruptPrivateKeyException"></exception>
		/// <exception cref="ArgumentOutOfRangeException"></exception>
		/// <exception cref="ArgumentNullException"></exception>
		public static MinisignPrivateKey LoadPrivateKeyFromString(string privateKeyString, string password)
		{
			if (string.IsNullOrEmpty(privateKeyString))
				throw new ArgumentException("privateKeyString can not be null", nameof(privateKeyString));

			if (string.IsNullOrEmpty(password))
				throw new ArgumentException("password can not be null", nameof(password));

			return LoadPrivateKey(Convert.FromBase64String(privateKeyString), Encoding.UTF8.GetBytes(password));
		}

		/// <summary>
		///     Load a private key from a file into a MinisignPrivateKey object.
		/// </summary>
		/// <param name="privateKeyFile">The full path to to the private key file.</param>
		/// <param name="password">The password to decrypt the private key.</param>
		/// <returns>A MinisignPrivateKey object.</returns>
		/// <exception cref="OverflowException"></exception>
		/// <exception cref="FileNotFoundException"></exception>
		/// <exception cref="ArgumentException"></exception>
		/// <exception cref="CorruptPrivateKeyException"></exception>
		/// <exception cref="ArgumentOutOfRangeException"></exception>
		/// <exception cref="ArgumentNullException"></exception>
		/// <exception cref="PathTooLongException"></exception>
		/// <exception cref="DirectoryNotFoundException"></exception>
		/// <exception cref="IOException"></exception>
		/// <exception cref="SecurityException"></exception>
		/// <exception cref="UnauthorizedAccessException"></exception>
		public static MinisignPrivateKey LoadPrivateKeyFromFile(string privateKeyFile, string password)
		{
			if (privateKeyFile != null && !File.Exists(privateKeyFile))
			{
				throw new FileNotFoundException("could not find privateKeyFile");
			}

			if (string.IsNullOrEmpty(password))
			{
				throw new ArgumentException("password can not be null", nameof(password));
			}

			var privateKeyLines = File.ReadLines(privateKeyFile).Take(2).ToList();
			if (privateKeyLines.Count != 2)
			{
				throw new CorruptPrivateKeyException("the private key file has missing lines");
			}

			// do some simple pre-validation
			if (!privateKeyLines[0].StartsWith(CommentPrefix))
			{
				throw new CorruptPrivateKeyException("the private key file has invalid lines");
			}

			return LoadPrivateKey(Convert.FromBase64String(privateKeyLines[1]), Encoding.UTF8.GetBytes(password));
		}

		/// <summary>
		///     Load a public key into a MinisignPublicKey object.
		/// </summary>
		/// <param name="privateKey">A valid private key.</param>
		/// <param name="password">The password to decrypt the private key.</param>
		/// <returns>A MinisignPrivateKey object.</returns>
		/// <exception cref="OverflowException"></exception>
		/// <exception cref="CorruptPrivateKeyException"></exception>
		/// <exception cref="ArgumentOutOfRangeException"></exception>
		/// <exception cref="ArgumentException"></exception>
		/// <exception cref="ArgumentNullException"></exception>
		public static MinisignPrivateKey LoadPrivateKey(byte[] privateKey, byte[] password)
		{
			if (privateKey == null)
				throw new ArgumentException("missing privateKey input", nameof(privateKey));

			if (password == null)
				throw new ArgumentException("missing password input", nameof(password));

			var minisignPrivateKey = new MinisignPrivateKey
			{
				SignatureAlgorithm = ArrayHelpers.SubArray(privateKey, 0, 2),
				KdfAlgorithm = ArrayHelpers.SubArray(privateKey, 2, 2),
				ChecksumAlgorithm = ArrayHelpers.SubArray(privateKey, 4, 2),
				KdfSalt = ArrayHelpers.SubArray(privateKey, 6, 32),
				KdfOpsLimit = BitConverter.ToInt64(ArrayHelpers.SubArray(privateKey, 38, 8), 0), //currently unused
				KdfMemLimit = BitConverter.ToInt64(ArrayHelpers.SubArray(privateKey, 46, 8), 0) //currently unused
			};

			if (!minisignPrivateKey.SignatureAlgorithm.SequenceEqual(Encoding.UTF8.GetBytes(Sigalg)))
			{
				throw new CorruptPrivateKeyException("bad SignatureAlgorithm");
			}

			if (!minisignPrivateKey.ChecksumAlgorithm.SequenceEqual(Encoding.UTF8.GetBytes(Chkalg)))
			{
				throw new CorruptPrivateKeyException("bad ChecksumAlgorithm");
			}

			if (!minisignPrivateKey.KdfAlgorithm.SequenceEqual(Encoding.UTF8.GetBytes(Kdfalg)))
			{
				throw new CorruptPrivateKeyException("bad KdfAlgorithm");
			}

			if (minisignPrivateKey.KdfSalt.Length != KeySaltBytes)
			{
				throw new CorruptPrivateKeyException("bad KdfSalt length");
			}

			var encryptedKeyData = ArrayHelpers.SubArray(privateKey, 54, 104);

			var decryptionKey = PasswordHash.ScryptHashBinary(password, minisignPrivateKey.KdfSalt,
				PasswordHash.Strength.Sensitive,
				104);

			var decryptedKeyData = EncryptionHelpers.Xor(encryptedKeyData, decryptionKey);
			minisignPrivateKey.KeyId = ArrayHelpers.SubArray(decryptedKeyData, 0, 8);
			minisignPrivateKey.SecretKey = ArrayHelpers.SubArray(decryptedKeyData, 8, 64);
			minisignPrivateKey.Checksum = ArrayHelpers.SubArray(decryptedKeyData, 72, 32);

			if (minisignPrivateKey.KeyId.Length != KeyNumBytes)
			{
				throw new CorruptPrivateKeyException("bad KeyId length");
			}

			var calculatedChecksum =
				GenericHash.Hash(
					ArrayHelpers.ConcatArrays(minisignPrivateKey.SignatureAlgorithm, minisignPrivateKey.KeyId,
						minisignPrivateKey.SecretKey), null, 32);

			if (!ArrayHelpers.ConstantTimeEquals(minisignPrivateKey.Checksum, calculatedChecksum))
			{
				throw new CorruptPrivateKeyException("bad private key checksum");
			}
			// extract the public key from the private key
			minisignPrivateKey.PublicKey =
				PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(minisignPrivateKey.SecretKey);

			return minisignPrivateKey;
		}

		#endregion

		#region Helper

		/// <summary>
		///     Loads a file into memory.
		/// </summary>
		/// <param name="messageFile">Path to the file.</param>
		/// <returns>The file as byte array.</returns>
		/// <exception cref="ArgumentException"></exception>
		/// <exception cref="FileNotFoundException"></exception>
		/// <exception cref="FileSizeExceededException"></exception>
		/// <exception cref="IOException"></exception>
		/// <exception cref="SecurityException"></exception>
		/// <exception cref="UnauthorizedAccessException"></exception>
		/// <exception cref="DirectoryNotFoundException"></exception>
		private static byte[] LoadMessageFile(string messageFile)
		{
			if (messageFile == null)
				throw new ArgumentException("missing messageFile input", nameof(messageFile));

			if (!File.Exists(messageFile))
			{
				throw new FileNotFoundException("could not find messageFile");
			}

			var messageFileLength = new FileInfo(messageFile);
			if (messageFileLength.Length >= MaxMessageFileSize)
			{
				throw new FileSizeExceededException("data has to be smaller than 1 Gb");
			}

			return File.ReadAllBytes(messageFile);
		}

		/// <summary>
		///     Computes a BLAKE2b-512 hash of a file without loading it fully into memory.
		///     Used for hashed minisign signatures.
		/// </summary>
		/// <param name="messageFile">Path to the file.</param>
		/// <returns>64-byte BLAKE2b hash of the file contents.</returns>
		/// <exception cref="ArgumentException"></exception>
		/// <exception cref="FileNotFoundException"></exception>
		/// <exception cref="IOException"></exception>
		/// <exception cref="SecurityException"></exception>
		/// <exception cref="UnauthorizedAccessException"></exception>
		/// <exception cref="DirectoryNotFoundException"></exception>
		private static byte[] ComputeBlake2bFileHash(string messageFile)
		{
			if (messageFile == null)
				throw new ArgumentException("missing messageFile input", nameof(messageFile));

			if (!File.Exists(messageFile))
				throw new FileNotFoundException("could not find messageFile");

			using (var stream = File.OpenRead(messageFile))
			using (var hashStream = new GenericHash.GenericHashAlgorithm((byte[])null, 64))
			{
				return hashStream.ComputeHash(stream);
			}
		}

		/// <summary>
		///     Get the current Unix Timestamp.
		/// </summary>
		/// <returns>The current Unix Timestamp.</returns>
		private static int GetTimestamp()
		{
			return (int)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds;
		}

		#endregion
	}
}
