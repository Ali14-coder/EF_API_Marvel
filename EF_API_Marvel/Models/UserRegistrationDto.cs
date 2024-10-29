namespace EF_API_Marvel.Models
{
    public class UserRegistrationDto
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string Role { get; set; } //"Admin" or "User"
    }
}
