using System.Collections.Generic;

namespace Minisign.Helper
{
    /// <summary>
    ///     Helper class for simple encryption.
    /// </summary>
    public static class EncryptionHelpers
    {
        /// <summary>
        ///     Encrypt an array with XOR.
        /// </summary>
        /// <param name="data">An unencrypted array.</param>
        /// <param name="keys">The encryption keys.</param>
        /// <returns>An encrypted array.</returns>
        public static byte[] Xor(byte[] data, IReadOnlyList<byte> keys)
        {
            for (var i = 0; i < data.Length; i++)
            {
                data[i] = (byte)(data[i] ^ keys[i]);
            }
            return data;
        }
    }
}
