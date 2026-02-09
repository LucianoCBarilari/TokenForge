namespace TokenForge.Application.Interfaces
{
    public interface IHelpers
    {
        bool EmailValidator(string email);
        bool AccountValidator(string account);
        bool PassValidator(string password);
        DateTime GetBuenosAiresTime();
    }
}
