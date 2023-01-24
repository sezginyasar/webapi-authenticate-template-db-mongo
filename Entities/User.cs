namespace webapiV2.Entities;

using System.Text.Json.Serialization;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

public class User
{
    public User(string username, string password, string passwordhash, string adi, string soyadi)
    {
        Adi = adi;
        Soyadi = soyadi;
        Username = username;
        Password = password;
        PasswordHash = passwordhash;
    }

    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = ObjectId.GenerateNewId().ToString();

    [BsonElement("Adi")]
    public string Adi { get; set; } = null!;

    [BsonElement("Soyadi")]
    public string Soyadi { get; set; } = null!;

    [BsonElement("Username")]
    [BsonRequired]
    public string Username { get; set; } = null!;

    // [BsonElement("Email")]
    // [BsonRequired]
    // public string Email { get; set; }

    //! JsonIgnore daha testler bittikten sonra açılacak.
    // [JsonIgnore]
    [BsonElement("Password")]
    [BsonRequired]
    public string Password { get; set; } = null!;

    //[JsonIgnore]
    public string? PasswordHash { get; set; } = null!;

    // [JsonIgnore]
    public List<RefreshToken>? RefreshTokens { get; set; }
}