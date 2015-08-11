namespace minisign.Models
{
    public class MinisignKeyPair
    {
        public MinisignPublicKey MinisignPublicKey { get; set; }
        public MinisignPrivateKey MinisignPrivateKey { get; set; }
        public string MinisignPublicKeyFilePath { get; set; }
        public string MinisignPrivateKeyFilePath { get; set; }
    }
}