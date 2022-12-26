namespace webapiV2.Models.Users;

using System.ComponentModel.DataAnnotations;
using webapiV2.Entities;

public class RegisterResponse
{
    [Required]
    public string Adi { get; set; }

    [Required]
    public string Soyadi { get; set; }

    [Required]
    public string Username { get; set; }

    [Required]
    public string Password { get; set; }
    public string PasswordHash { get; set; }


    public RegisterResponse(User user)
    {
        Adi = user.Adi;
        Soyadi = user.Soyadi;
        // Email = user.Email;
        Username = user.Username;
        //! daha sonra düz password yazılan kısım silinecek
        Password = user.Password;
        PasswordHash = user.PasswordHash;
    }
}