namespace webapiV2.Models.Users;

using System.ComponentModel.DataAnnotations;

public class RegisterRequest
{
    [Required]
    public string Adi { get; set; }= null!;

    [Required]
    public string Soyadi { get; set; }= null!;

    [Required]
    public string Username { get; set; }= null!;

    [Required]
    public string Password { get; set; }= null!;
}