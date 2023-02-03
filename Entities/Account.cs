namespace webapiV2.Entities;

using System.Text.Json.Serialization;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
public class Account {
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = ObjectId.GenerateNewId().ToString();
    public string Adi { get; set; }
    public string Soyadi { get; set; }
    public string Email { get; set; }
    //! daha sonra silinecek
    public string? Password { get; set; }

    //! JsonIgnore daha testler bittikten sonra açılacak.
    [JsonIgnore]
    public string PasswordHash { get; set; }
    public bool AcceptTerms { get; set; }
    public Role Role { get; set; }
    public string? VerificationToken { get; set; }
    public DateTime? Verified { get; set; }
    public bool IsVerified => Verified.HasValue || PasswordReset.HasValue;
    public string? ResetToken { get; set; }
    public DateTime? ResetTokenExpires { get; set; }
    public DateTime? PasswordReset { get; set; }
    public DateTime Created { get; set; }
    public DateTime? Updated { get; set; }
    public List<RefreshToken>? RefreshTokens { get; set; }
    public bool IsDisabled { get; set; } = false;

    // public bool OwnsToken(string token) {
    //     return this.RefreshTokens?.Find(x => x.Token == token) != null;
    // }
}