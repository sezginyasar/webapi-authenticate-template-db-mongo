namespace webapiV2.Models.Users;

public class UpdateRequest
{
    public string Adi { get; set; } = null!;
    public string Soyadi { get; set; } = null!;
    public string Username { get; set; } = null!;
    public string Password { get; set; } = null!;
}