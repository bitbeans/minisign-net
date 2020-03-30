using Minisign;
using Sodium;
using System.IO;
using System.Text;
using Xunit;

namespace Tests
{
    public class BaseTests
    {
        [Fact]
        public void GenerateKeyTest()
        {
            const string seckeypass = "7e725ac9f52336f74dc54bbe2912855f79baacc08b008437809fq5527f1b2256";

            var minisignKeyPair = Core.GenerateKeyPair(seckeypass, true, "Data");
            Assert.True(File.Exists(minisignKeyPair.MinisignPrivateKeyFilePath));
            Assert.True(File.Exists(minisignKeyPair.MinisignPublicKeyFilePath));

            var minisignPrivateKey = Core.LoadPrivateKeyFromFile(minisignKeyPair.MinisignPrivateKeyFilePath, seckeypass);
            var minisignPublicKey = Core.LoadPublicKeyFromFile(minisignKeyPair.MinisignPublicKeyFilePath);

            Assert.Equal(minisignPublicKey.KeyId, minisignPrivateKey.KeyId);

            File.Delete(minisignKeyPair.MinisignPrivateKeyFilePath);
            File.Delete(minisignKeyPair.MinisignPublicKeyFilePath);
        }

        [Fact]
        public void SignTest()
        {
            const string expected = "9d6f33b5e347042e";
            const string seckeypass = "7e725ac9f52336f74dc54bbe2912855f79baacc08b008437809fq5527f1b2256";
            const string privateKey = "456453634232aeb543fbea3467ad996ac237b38646bcbc12e6232fbc0a8cd9a1ed46c7263af200000002000000000000004000000000992f22d875591d3bb7dc3f77caba3229e2f7b8afe655140bafabcb6c5d8b259366a2897624de65743de71f8f2dcc545a96c4b530ffd796d92f35eb02425f4196ab9a37ff2f542774d676625f8de689fa2da3e0a0250efd58347c35b927ca49ec4d93687be59d6e1a";
            var minisignPrivateKey = Core.LoadPrivateKey(Utilities.HexToBinary(privateKey), Encoding.UTF8.GetBytes(seckeypass));

            var file = Path.Combine("Data", "testfile.jpg");
            var signedFile = Core.Sign(file, minisignPrivateKey);

            var minisignSignature = Core.LoadSignatureFromFile(signedFile);
            var minisignPublicKey = Core.LoadPublicKeyFromFile(Path.Combine("Data", "test.pub"));
            Assert.Equal(expected, Utilities.BinaryToHex(minisignSignature.KeyId));
            Assert.Equal(expected, Utilities.BinaryToHex(minisignPublicKey.KeyId));

            Assert.True(Core.ValidateSignature(file, minisignSignature, minisignPublicKey));
            File.Delete(signedFile);
        }

        [Fact]
        public void Sign2Test()
        {
            const string expected = "9d6f33b5e347042e";
            const string seckeypass = "7e725ac9f52336f74dc54bbe2912855f79baacc08b008437809fq5527f1b2256";
            const string privateKey = "456453634232aeb543fbea3467ad996ac237b38646bcbc12e6232fbc0a8cd9a1ed46c7263af200000002000000000000004000000000992f22d875591d3bb7dc3f77caba3229e2f7b8afe655140bafabcb6c5d8b259366a2897624de65743de71f8f2dcc545a96c4b530ffd796d92f35eb02425f4196ab9a37ff2f542774d676625f8de689fa2da3e0a0250efd58347c35b927ca49ec4d93687be59d6e1a";
            var minisignPrivateKey = Core.LoadPrivateKey(Utilities.HexToBinary(privateKey), Encoding.UTF8.GetBytes(seckeypass));

            var file = Path.Combine("Data", "testfile.jpg");
            var fileBinary = File.ReadAllBytes(file);
            var signedFile = Core.Sign(file, minisignPrivateKey);

            var minisignSignature = Core.LoadSignatureFromFile(signedFile);
            var minisignPublicKey = Core.LoadPublicKeyFromFile(Path.Combine("Data", "test.pub"));
            Assert.Equal(expected, Utilities.BinaryToHex(minisignSignature.KeyId));
            Assert.Equal(expected, Utilities.BinaryToHex(minisignPublicKey.KeyId));

            Assert.True(Core.ValidateSignature(fileBinary, minisignSignature, minisignPublicKey));
            File.Delete(signedFile);
        }


        [Fact]
        public void LoadSignatureFromStringTest()
        {
            const string expected = "9d6f33b5e347042e";
            const string signatureString = "RWSdbzO140cELi+edKSQMZw/yrCDB3aetMNoPYsESNapZuUfHeE8JunmfFNykkZbXWRMy+0Y8aaONyhdGSZtbEXlw32RpDtMmgw=";
            const string trustedComment = "trusted comment: timestamp: 1439294334 file: testfile.jpg";
            const string globalSignature = "sXw0VdGKvIgZibPYp9bR5jz01dRkBbWzEBFLpY/+u7MGwk4HJT/Kj8aB1iXW3w6n9/gSv33cd2sk7uDVFclIAA==";
            var minisignSignature = Core.LoadSignatureFromString(signatureString, trustedComment, globalSignature);
            Assert.Equal(expected, Utilities.BinaryToHex(minisignSignature.KeyId));
        }

        [Fact]
        public void LoadSignatureFromFileTest()
        {
            const string expected = "9d6f33b5e347042e";
            var file = Path.Combine("Data", "test.jpg.minisig");
            var minisignSignature = Core.LoadSignatureFromFile(file);
            Assert.Equal(expected, Utilities.BinaryToHex(minisignSignature.KeyId));
        }

        [Fact]
        public void LoadPublicKeyFromStringTest()
        {
            const string expected = "9d6f33b5e347042e";
            var minisignPublicKey = Core.LoadPublicKeyFromString("RWSdbzO140cELjh8lkBoBpp/UBg1pd9NgoPZF+y6ZSsEjavog68aNfMF");
            Assert.Equal(expected, Utilities.BinaryToHex(minisignPublicKey.KeyId));
        }

        [Fact]
        public void LoadPublicKeyFromFileTest()
        {
            const string expected = "9d6f33b5e347042e";
            var file = Path.Combine("Data", "test.pub");
            var minisignPublicKey = Core.LoadPublicKeyFromFile(file);
            Assert.Equal(expected, Utilities.BinaryToHex(minisignPublicKey.KeyId));
        }

        [Fact]
        public void LoadPrivateKeyTest()
        {
            const string seckeypass = "7e725ac9f52336f74dc54bbe2912855f79baacc08b008437809fq5527f1b2256";
            const string expected =
                "521437eb06d390e3881d6227543c670bd79ce4092845a4d567e85013c6ffe454387c964068069a7f501835a5df4d8283d917ecba652b048dabe883af1a35f305";
            const string privateKey = "456453634232aeb543fbea3467ad996ac237b38646bcbc12e6232fbc0a8cd9a1ed46c7263af200000002000000000000004000000000992f22d875591d3bb7dc3f77caba3229e2f7b8afe655140bafabcb6c5d8b259366a2897624de65743de71f8f2dcc545a96c4b530ffd796d92f35eb02425f4196ab9a37ff2f542774d676625f8de689fa2da3e0a0250efd58347c35b927ca49ec4d93687be59d6e1a";
            var minisignPrivateKey = Core.LoadPrivateKey(Utilities.HexToBinary(privateKey), Encoding.UTF8.GetBytes(seckeypass));
            Assert.Equal(expected, Utilities.BinaryToHex(minisignPrivateKey.SecretKey));
        }

        [Fact]
        public void LoadPrivateKeyFromStringTest()
        {
            const string seckeypass = "7e725ac9f52336f74dc54bbe2912855f79baacc08b008437809fq5527f1b2256";
            const string expected =
                "521437eb06d390e3881d6227543c670bd79ce4092845a4d567e85013c6ffe454387c964068069a7f501835a5df4d8283d917ecba652b048dabe883af1a35f305";
            var minisignPrivateKey = Core.LoadPrivateKeyFromString("RWRTY0IyrrVD++o0Z62ZasI3s4ZGvLwS5iMvvAqM2aHtRscmOvIAAAACAAAAAAAAAEAAAAAAmS8i2HVZHTu33D93yroyKeL3uK/mVRQLr6vLbF2LJZNmool2JN5ldD3nH48tzFRalsS1MP/XltkvNesCQl9BlquaN/8vVCd01nZiX43mifoto+CgJQ79WDR8NbknyknsTZNoe+Wdbho=", seckeypass);
            Assert.Equal(expected, Utilities.BinaryToHex(minisignPrivateKey.SecretKey));
        }

        [Fact]
        public void LoadPrivateKeyFromFileTest()
        {
            const string seckeypass = "7e725ac9f52336f74dc54bbe2912855f79baacc08b008437809fq5527f1b2256";
            const string expected =
                "521437eb06d390e3881d6227543c670bd79ce4092845a4d567e85013c6ffe454387c964068069a7f501835a5df4d8283d917ecba652b048dabe883af1a35f305";
            var file = Path.Combine("Data", "test.key");
            var minisignPrivateKey = Core.LoadPrivateKeyFromFile(file, seckeypass);
            Assert.Equal(expected, Utilities.BinaryToHex(minisignPrivateKey.SecretKey));
        }
    }
}
