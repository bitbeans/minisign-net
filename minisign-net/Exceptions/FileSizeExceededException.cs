using System;

namespace minisign.Exceptions
{
    public class FileSizeExceededException : Exception
    {
        public FileSizeExceededException()
        {
        }

        public FileSizeExceededException(string message)
            : base(message)
        {
        }

        public FileSizeExceededException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}
