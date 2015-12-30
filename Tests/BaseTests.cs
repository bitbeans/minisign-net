using System;
using System.IO;
using System.Text;
using minisign;
using minisign.Exceptions;
using NUnit.Framework;
using Sodium;

namespace Tests
{
    [TestFixture]
    public class BaseTests
    {
        [Test]
        public void GenerateKeyTest()
        {
            const string seckeypass = "7e725ac9f52336f74dc54bbe2912855f79baacc08b008437809fq5527f1b2256";
            const string testfolder = "Testfolder";

            var minisignKeyPair = Minisign.GenerateKeyPair(seckeypass, true, testfolder);
            
            Assert.AreEqual(true,File.Exists(minisignKeyPair.MinisignPrivateKeyFilePath));
            Assert.AreEqual(true, File.Exists(minisignKeyPair.MinisignPublicKeyFilePath));

            var minisignPrivateKey = Minisign.LoadPrivateKeyFromFile(minisignKeyPair.MinisignPrivateKeyFilePath, seckeypass);
            var minisignPublicKey = Minisign.LoadPublicKeyFromFile(minisignKeyPair.MinisignPublicKeyFilePath);

            Assert.AreEqual(minisignPublicKey.KeyId, minisignPrivateKey.KeyId);

            File.Delete(minisignKeyPair.MinisignPrivateKeyFilePath);
            File.Delete(minisignKeyPair.MinisignPublicKeyFilePath);
        }

        [Test]
        public void SignTest()
        {
            const string testfolder = "Testfolder";
            const string expected = "9d6f33b5e347042e";
            const string seckeypass = "7e725ac9f52336f74dc54bbe2912855f79baacc08b008437809fq5527f1b2256";
            const string privateKey = "456453634232aeb543fbea3467ad996ac237b38646bcbc12e6232fbc0a8cd9a1ed46c7263af200000002000000000000004000000000992f22d875591d3bb7dc3f77caba3229e2f7b8afe655140bafabcb6c5d8b259366a2897624de65743de71f8f2dcc545a96c4b530ffd796d92f35eb02425f4196ab9a37ff2f542774d676625f8de689fa2da3e0a0250efd58347c35b927ca49ec4d93687be59d6e1a";
            var minisignPrivateKey = Minisign.LoadPrivateKey(Utilities.HexToBinary(privateKey), Encoding.UTF8.GetBytes(seckeypass));

            var file = Path.Combine(testfolder, "testfile.jpg");
            var signedFile = Minisign.Sign(file, minisignPrivateKey);

            var minisignSignature = Minisign.LoadSignatureFromFile(signedFile);
            var minisignPublicKey = Minisign.LoadPublicKeyFromFile(Path.Combine(testfolder, "test.pub"));
            Assert.AreEqual(expected, Utilities.BinaryToHex(minisignSignature.KeyId));
            Assert.AreEqual(expected, Utilities.BinaryToHex(minisignPublicKey.KeyId));

            Assert.AreEqual(true, Minisign.ValidateSignature(file, minisignSignature, minisignPublicKey));
            File.Delete(signedFile);
        }

        [Test]
        public void Sign2Test()
        {
            const string testfolder = "Testfolder";
            const string expected = "9d6f33b5e347042e";
            const string seckeypass = "7e725ac9f52336f74dc54bbe2912855f79baacc08b008437809fq5527f1b2256";
            const string privateKey = "456453634232aeb543fbea3467ad996ac237b38646bcbc12e6232fbc0a8cd9a1ed46c7263af200000002000000000000004000000000992f22d875591d3bb7dc3f77caba3229e2f7b8afe655140bafabcb6c5d8b259366a2897624de65743de71f8f2dcc545a96c4b530ffd796d92f35eb02425f4196ab9a37ff2f542774d676625f8de689fa2da3e0a0250efd58347c35b927ca49ec4d93687be59d6e1a";
            var minisignPrivateKey = Minisign.LoadPrivateKey(Utilities.HexToBinary(privateKey), Encoding.UTF8.GetBytes(seckeypass));

            var file = Path.Combine(testfolder, "testfile.jpg");
            var fileBinary = File.ReadAllBytes(file);
            var signedFile = Minisign.Sign(file, minisignPrivateKey);

            var minisignSignature = Minisign.LoadSignatureFromFile(signedFile);
            var minisignPublicKey = Minisign.LoadPublicKeyFromFile(Path.Combine(testfolder, "test.pub"));
            Assert.AreEqual(expected, Utilities.BinaryToHex(minisignSignature.KeyId));
            Assert.AreEqual(expected, Utilities.BinaryToHex(minisignPublicKey.KeyId));

            Assert.AreEqual(true, Minisign.ValidateSignature(fileBinary, minisignSignature, minisignPublicKey));
            File.Delete(signedFile);
        }
        

        [Test]
        public void LoadSignatureFromStringTest()
        {
            const string expected = "9d6f33b5e347042e";
            const string signatureString = "RWSdbzO140cELi+edKSQMZw/yrCDB3aetMNoPYsESNapZuUfHeE8JunmfFNykkZbXWRMy+0Y8aaONyhdGSZtbEXlw32RpDtMmgw=";
            const string trustedComment = "trusted comment: timestamp: 1439294334 file: testfile.jpg";
            const string globalSignature = "sXw0VdGKvIgZibPYp9bR5jz01dRkBbWzEBFLpY/+u7MGwk4HJT/Kj8aB1iXW3w6n9/gSv33cd2sk7uDVFclIAA==";
            var minisignSignature = Minisign.LoadSignatureFromString(signatureString, trustedComment, globalSignature);
            Assert.AreEqual(expected, Utilities.BinaryToHex(minisignSignature.KeyId));
        }

        [Test]
        public void LoadSignatureFromFileTest()
        {
            const string expected = "9d6f33b5e347042e";
            const string testfolder = "Testfolder";
            var file = Path.Combine(testfolder, "test.jpg.minisig");
            var minisignSignature = Minisign.LoadSignatureFromFile(file);
            Assert.AreEqual(expected, Utilities.BinaryToHex(minisignSignature.KeyId));
        }

        [Test]
        public void LoadPublicKeyFromStringTest()
        {
            const string expected = "9d6f33b5e347042e";
            var minisignPublicKey = Minisign.LoadPublicKeyFromString("RWSdbzO140cELjh8lkBoBpp/UBg1pd9NgoPZF+y6ZSsEjavog68aNfMF");
            Assert.AreEqual(expected, Utilities.BinaryToHex(minisignPublicKey.KeyId));
        }

        [Test]
        public void LoadPublicKeyFromFileTest()
        {
            const string expected = "9d6f33b5e347042e";
            const string testfolder = "Testfolder";
            var file = Path.Combine(testfolder, "test.pub");
            var minisignPublicKey = Minisign.LoadPublicKeyFromFile(file);
            Assert.AreEqual(expected, Utilities.BinaryToHex(minisignPublicKey.KeyId));
        }

        [Test]
        public void LoadPrivateKeyTest()
        {
            const string seckeypass = "7e725ac9f52336f74dc54bbe2912855f79baacc08b008437809fq5527f1b2256";
            const string expected =
                "521437eb06d390e3881d6227543c670bd79ce4092845a4d567e85013c6ffe454387c964068069a7f501835a5df4d8283d917ecba652b048dabe883af1a35f305";
            const string privateKey = "456453634232aeb543fbea3467ad996ac237b38646bcbc12e6232fbc0a8cd9a1ed46c7263af200000002000000000000004000000000992f22d875591d3bb7dc3f77caba3229e2f7b8afe655140bafabcb6c5d8b259366a2897624de65743de71f8f2dcc545a96c4b530ffd796d92f35eb02425f4196ab9a37ff2f542774d676625f8de689fa2da3e0a0250efd58347c35b927ca49ec4d93687be59d6e1a";
            var minisignPrivateKey = Minisign.LoadPrivateKey(Utilities.HexToBinary(privateKey), Encoding.UTF8.GetBytes(seckeypass));
            Assert.AreEqual(expected, Utilities.BinaryToHex(minisignPrivateKey.SecretKey));
        }

        [Test]
        public void LoadPrivateKeyFromStringTest()
        {
            const string seckeypass = "7e725ac9f52336f74dc54bbe2912855f79baacc08b008437809fq5527f1b2256";
            const string expected =
                "521437eb06d390e3881d6227543c670bd79ce4092845a4d567e85013c6ffe454387c964068069a7f501835a5df4d8283d917ecba652b048dabe883af1a35f305";
            var minisignPrivateKey = Minisign.LoadPrivateKeyFromString("RWRTY0IyrrVD++o0Z62ZasI3s4ZGvLwS5iMvvAqM2aHtRscmOvIAAAACAAAAAAAAAEAAAAAAmS8i2HVZHTu33D93yroyKeL3uK/mVRQLr6vLbF2LJZNmool2JN5ldD3nH48tzFRalsS1MP/XltkvNesCQl9BlquaN/8vVCd01nZiX43mifoto+CgJQ79WDR8NbknyknsTZNoe+Wdbho=", seckeypass);
            Assert.AreEqual(expected, Utilities.BinaryToHex(minisignPrivateKey.SecretKey));
        }

        [Test]
        public void LoadPrivateKeyFromFileTest()
        {
            const string seckeypass = "7e725ac9f52336f74dc54bbe2912855f79baacc08b008437809fq5527f1b2256";
            const string expected =
                "521437eb06d390e3881d6227543c670bd79ce4092845a4d567e85013c6ffe454387c964068069a7f501835a5df4d8283d917ecba652b048dabe883af1a35f305";
            const string testfolder = "Testfolder";
            var file = Path.Combine(testfolder, "test.key");
            var minisignPrivateKey = Minisign.LoadPrivateKeyFromFile(file, seckeypass);
            Assert.AreEqual(expected, Utilities.BinaryToHex(minisignPrivateKey.SecretKey));
        }
    }
}
