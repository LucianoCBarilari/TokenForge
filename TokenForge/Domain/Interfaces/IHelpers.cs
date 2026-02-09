namespace TokenForge.Domain.Interfaces
{
    public interface IHelpers
    {
        public DateTime GetBuenosAiresTime();
        public bool EmailValidator(string Email);
        public bool AccountValidator(string UserAccount);
        public bool PassValidator(string Pass);
    }
}

