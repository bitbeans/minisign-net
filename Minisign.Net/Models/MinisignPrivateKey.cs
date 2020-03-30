namespace Minisign.Models
{
    public class MinisignPrivateKey
    {
        public byte[] SignatureAlgorithm { get; set; }
        public byte[] KdfAlgorithm { get; set; }
        public byte[] ChecksumAlgorithm { get; set; }
        public byte[] KdfSalt { get; set; }
        public long KdfOpsLimit { get; set; }
        public long KdfMemLimit { get; set; }
        public byte[] KeyId { get; set; }
        public byte[] SecretKey { get; set; }
        public byte[] PublicKey { get; set; }
        public byte[] Checksum { get; set; }
    }
}
