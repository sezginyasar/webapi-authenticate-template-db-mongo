namespace webapiV2.Entities;

using System.Text.Json.Serialization;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

public class User
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    [BsonElement("Adi")]
    public string? Adi { get; set; } = null!;

    [BsonElement("Soyadi")]
    public string? Soyadi { get; set; } = null!;

    [BsonElement("KullaniciAdi")]
    [BsonRequired]
    public string Username { get; set; }

    // [BsonElement("Email")]
    // [BsonRequired]
    // public string Email { get; set; }

    // [JsonIgnore]
    [BsonElement("Password")]
    [BsonRequired]
    public string Password { get; set; }

    //[JsonIgnore]
    public string? PasswordHash { get; set; } = null!;
}