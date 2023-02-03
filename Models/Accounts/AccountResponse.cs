using webapiV2.Entities;

namespace webapiV2.Models.Accounts;

public class AccountResponse {
    public string Id { get; set; }
    public string Adi { get; set; }
    public string Soyadi { get; set; }
    public string Email { get; set; }
    public Role Role { get; set; }
    public DateTime Created { get; set; }
    public DateTime? Updated { get; set; }
    public bool IsVerified { get; set; }

    public AccountResponse(Account account) {
        Id = account.Id;
        Adi = account.Adi;
        Soyadi = account.Soyadi;
        Email = account.Email;
        Role = account.Role;
        Created = account.Created;
        Updated = account.Updated;
        IsVerified = account.IsVerified;
    }
}