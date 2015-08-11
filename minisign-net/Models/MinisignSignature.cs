namespace minisign.Models
{
    public class MinisignSignature
    {
        public byte[] SignatureAlgorithm { get; set; }
        public byte[] KeyId { get; set; }
        public byte[] Signature { get; set; }
        public byte[] GlobalSignature { get; set; }
        public byte[] TrustedComment { get; set; }
    }
}