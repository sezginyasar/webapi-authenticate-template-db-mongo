namespace webapiV2.Models.Users;

using System.ComponentModel.DataAnnotations;

public class RegisterRequest
{
    [Required]
    public string Adi { get; set; }

    [Required]
    public string Soyadi { get; set; }

    [Required]
    public string Username { get; set; }

    [Required]
    public string Password { get; set; }
}