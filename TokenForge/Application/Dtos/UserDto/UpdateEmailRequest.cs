namespace TokenForge.Application.Dtos.UserDto
{
    public class UpdateEmailRequest
    {
        public Guid UserId { get; set; }
        public string NewEmail { get; set; } = string.Empty;
    }
}


