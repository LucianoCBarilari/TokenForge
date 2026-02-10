using TokenForge.Domain.Shared;

namespace TokenForge.WebApi.Models
{
    public sealed class ApiResponse
    {
        public int StatusCode { get; init; }
        public bool Success { get; init; }
        public string? Message { get; init; }
        public object? Result { get; init; }
        public Error[]? Errors { get; init; }
        public string? TraceId { get; init; }

        public static ApiResponse SuccessResponse(object? result, string? message, int statusCode, string? traceId)
        {
            return new ApiResponse
            {
                StatusCode = statusCode,
                Success = true,
                Message = message,
                Result = result,
                Errors = null,
                TraceId = traceId
            };
        }

        public static ApiResponse FailureResponse(Error[] errors, string? message, int statusCode, string? traceId)
        {
            return new ApiResponse
            {
                StatusCode = statusCode,
                Success = false,
                Message = message,
                Result = null,
                Errors = errors,
                TraceId = traceId
            };
        }
    }
}

