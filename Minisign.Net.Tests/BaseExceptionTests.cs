using System.IO;
using Minisign;
using Xunit;

namespace Tests
{
    public class BaseExceptionTests
    {
        [Fact]
        public void GenerateKeyBaseFolderTest()
        {
            const string seckeypass = "7e725ac9f52336f74dc54bbe2912855f79baacc08b008437809fq5527f1b2256";
            const string folder = "Test";
            Assert.Throws<DirectoryNotFoundException>(
                () => { Core.GenerateKeyPair(seckeypass, true, folder); });
        }
    }
}
