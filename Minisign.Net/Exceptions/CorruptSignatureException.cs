using System;

namespace Minisign.Exceptions
{
    public class CorruptSignatureException : Exception
    {
        public CorruptSignatureException()
        {
        }

        public CorruptSignatureException(string message)
            : base(message)
        {
        }

        public CorruptSignatureException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}
