namespace webapiV2.Models.Users;

using System.Text.Json.Serialization;
using webapiV2.Entities;

public class AuthenticateResponse
{
    public string Id { get; set; }
    public string Adi { get; set; }
    public string Soyadi { get; set; }
    //public string Email { get; set; }
    public string Username { get; set; }
    public string JwtToken { get; set; }

    //[JsonIgnore] // refresh token is returned in http only cookie
    public string RefreshToken { get; set; }

    public AuthenticateResponse(User user, string jwtToken, string refreshToken)
    {
        Id = user.Id;
        Adi = user.Adi;
        Soyadi = user.Soyadi;
        // Email = user.Email;
        Username = user.Username;
        JwtToken = jwtToken;
        RefreshToken = refreshToken;
    }
}