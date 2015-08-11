using System.IO;
using minisign;
using NUnit.Framework;

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
    }
}
