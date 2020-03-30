namespace Minisign.Models
{
    public class MinisignPublicKey
    {
        public byte[] SignatureAlgorithm { get; set; }
        public byte[] KeyId { get; set; }
        public byte[] PublicKey { get; set; }
    }
}
