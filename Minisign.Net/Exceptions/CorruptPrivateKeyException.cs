using System;

namespace Minisign.Exceptions
{
    public class CorruptPrivateKeyException : Exception
    {
        public CorruptPrivateKeyException()
        {
        }

        public CorruptPrivateKeyException(string message)
            : base(message)
        {
        }

        public CorruptPrivateKeyException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}
