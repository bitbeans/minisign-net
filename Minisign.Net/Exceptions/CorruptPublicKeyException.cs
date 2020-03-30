using System;

namespace Minisign.Exceptions
{
    public class CorruptPublicKeyException : Exception
    {
        public CorruptPublicKeyException()
        {
        }

        public CorruptPublicKeyException(string message)
            : base(message)
        {
        }

        public CorruptPublicKeyException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}
