namespace TokenForge.Domain.Shared
{
    public class Result
    {
        public bool IsSuccess { get; }
        public bool IsFailure => !IsSuccess;
        public Error Error { get; }

        protected Result(bool isSuccess, Error error)
        {
            if (isSuccess && error != Error.None)
            {
                throw new InvalidOperationException("Success result cannot have an error.");
            }

            if (!isSuccess && error == Error.None)
            {
                throw new InvalidOperationException("Failure result must have an error.");
            }

            IsSuccess = isSuccess;
            Error = error;
        }

        public static Result Success() => new(true, Error.None);
        public static Result Failure(Error error) => new(false, error);
    }

    public class Result<T> : Result
    {
        public T Value { get; }

        private Result(T value) : base(true, Error.None)
        {
            Value = value;
        }

        private Result(Error error) : base(false, error)
        {
            Value = default!;
        }

        public static Result<T> Success(T value) => new(value);
        public static new Result<T> Failure(Error error) => new(error);

        public static implicit operator Result<T>(T value) => Success(value);
        public static implicit operator Result<T>(Error error) => Failure(error);
    }
}
