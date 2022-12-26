namespace webapiV2.Models;

using webapiV2.Entities;

public class AuthenticateResponse
{
    public string Id { get; set; }
    public string Adi { get; set; }
    public string Soyadi { get; set; }
    public string Email { get; set; }
    public string Username { get; set; }
    public string Token { get; set; }

    public AuthenticateResponse(User user, string token)
    {
        Id = user.Id;
        Adi = user.Adi;
        Soyadi = user.Soyadi;
        // Email = user.Email;
        Username = user.Username;
        Token = token;
    }
}