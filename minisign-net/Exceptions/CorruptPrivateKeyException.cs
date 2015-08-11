using System;

namespace minisign.Exceptions
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
