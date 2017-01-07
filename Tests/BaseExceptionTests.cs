using System.IO;
using minisign;
using NUnit.Framework;

namespace Tests
{
    [TestFixture]
    public class BaseExceptionTests
    {
        [Test]
        public void GenerateKeyBaseFolderTest()
        {
            const string seckeypass = "7e725ac9f52336f74dc54bbe2912855f79baacc08b008437809fq5527f1b2256";
            const string folder = "Test";

			Assert.Throws<DirectoryNotFoundException>(
				() => { Minisign.GenerateKeyPair(seckeypass, true, folder); });
        }
    }
}
