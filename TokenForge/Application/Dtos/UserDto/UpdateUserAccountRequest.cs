namespace TokenForge.Application.Dtos.UserDto
{
    public class UpdateUserAccountRequest
    {
        public Guid UserId { get; set; }
        public string NewAccount { get; set; } = string.Empty;
    }
}


