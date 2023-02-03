namespace webapiV2.Models.Accounts;

using System.Text.Json.Serialization;
using webapiV2.Entities;

public class AuthenticateResponse {
    public string Id { get; set; }
    public string Adi { get; set; }
    public string Soyadi { get; set; }
    public string Email { get; set; }
    public string Role { get; set; }
    public DateTime Created { get; set; }
    public DateTime? Updated { get; set; }
    public bool IsVerified { get; set; }
    public string JwtToken { get; set; }

    //! JsonIgnore daha testler bittikten sonra açılacak.
    [JsonIgnore] 
    // refresh token is returned in http only cookie
    public string RefreshToken { get; set; }

    public AuthenticateResponse(Account account, string jwtToken, string refreshToken) {
        Id = account.Id;
        Adi = account.Adi;
        Soyadi = account.Soyadi;
        Email = account.Email;
        Role = account.Role.ToString();
        Created = account.Created;
        Updated = account.Updated;
        IsVerified = account.IsVerified;
        JwtToken = jwtToken;
        RefreshToken = refreshToken;
    }
}