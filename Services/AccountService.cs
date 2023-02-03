namespace webapiV2.Services;

using BCrypt.Net;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Driver;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using webapiV2.Database;
using webapiV2.Entities;
using webapiV2.Authorization;
using webapiV2.Models.Accounts;
using webapiV2.Helpers;
using System.Security.Cryptography;

public interface IAccountService {
    AuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress);
    AuthenticateResponse RefreshToken(string token, string ipAddress);
    void RevokeToken(string token, string ipAddress);
    void Register(RegisterRequest model, string origin);
    void VerifyEmail(string token);
    void ForgotPassword(ForgotPasswordRequest model, string origin);
    void ValidateResetToken(ValidateResetTokenRequest model);
    void ResetPassword(ResetPasswordRequest model);
    IEnumerable<AccountResponse> GetAll();
    AccountResponse GetById(string id);
    AccountResponse Create(CreateRequest model);
    AccountResponse Update(string id, UpdateRequest model);
    void Delete(string id);
    bool OwnsToken(string token, string id);
}

public class AccountService : IAccountService {
    private readonly IMongoCollection<Account> _accounts;
    private IJwtUtils _jwtUtils;
    private readonly AppSettings _appSettings;
    private readonly IEmailService _emailService;

    // users hardcoded for simplicity, store in a db with hashed passwords in production applications
    // private List<User> _users = new List<User>
    // {
    //     new User { Id = "1", Adi = "Test", Soyadi = "User", Username = "test", Password = "test" }
    // };

    //private readonly AppSettings _appSettings;
    //IOptions<AppSettings> appSettings,
    public AccountService(IOptions<DatabaseSettings> db, IJwtUtils jwtUtils, IOptions<AppSettings> appSettings, IEmailService emailService) {
        var mongoClient = new MongoClient(db.Value.ConnectionString);
        var mongoDatabase = mongoClient.GetDatabase(db.Value.DatabaseName);

        _accounts = mongoDatabase.GetCollection<Account>("Accounts");
        _jwtUtils = jwtUtils;
        _appSettings = appSettings.Value;
        _emailService = emailService;
    }

    public AuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress) {
        var account = this._accounts.Find(x => x.Email == model.Email).SingleOrDefault();
        // validate
        if (account == null || !account.IsVerified || !BCrypt.Verify(model.Password, account.PasswordHash) || account.IsDisabled)
            throw new AppException("Email adresi veya şifre yanlış. Lütfen sistem yöneticiniz ile görüşünüz!");

        // authentication successful so generate jwt token and refresh tokens
        var jwtToken = _jwtUtils.GenerateJwtToken(account);
        var refreshToken = _jwtUtils.GenerateRefreshToken(ipAddress);
        var filter = Builders<Account>.Filter.Eq("Id", account.Id);
        var push = Builders<Account>.Update.Push("RefreshTokens", refreshToken);
        _accounts.UpdateOne(filter, push);

        // remove old refresh tokens from user
        removeOldRefreshTokens(account);

        return new AuthenticateResponse(account, jwtToken, refreshToken.Token);
    }

    public AuthenticateResponse RefreshToken(string token, string ipAddress) {
        var account = getAccountByRefreshToken(token);
        var refreshToken = account.RefreshTokens.Single(x => x.Token == token);
        var filter = Builders<Account>.Filter.Eq("Id", account.Id);

        if (refreshToken.IsRevoked) {
            // revoke all descendant tokens in case this token has been compromised
            revokeDescendantRefreshTokens(refreshToken, account, ipAddress, $"Attempted reuse of revoked ancestor token: {token}");
            var updateRefreshToken = Builders<Account>.Update.Set(x => x.RefreshTokens, account.RefreshTokens);
            _accounts.UpdateOne(filter, updateRefreshToken);
        }

        if (!refreshToken.IsActive)
            throw new AppException("Invalid token");

        // replace old refresh token with a new one (rotate token)
        var newRefreshToken = rotateRefreshToken(refreshToken, ipAddress);
        account.RefreshTokens.Add(newRefreshToken);

        // remove old refresh tokens from account
        removeOldRefreshTokens(account);

        // save changes to db
        var update = Builders<Account>.Update.Set("RefreshTokens", account.RefreshTokens);
        _accounts.UpdateOne(filter, update);

        // generate new jwt
        var jwtToken = _jwtUtils.GenerateJwtToken(account);

        return new AuthenticateResponse(account, jwtToken, newRefreshToken.Token);
    }

    public void RevokeToken(string token, string ipAddress) {
        var account = getAccountByRefreshToken(token);
        var refreshToken = account.RefreshTokens.Single(x => x.Token == token);
        var filter = Builders<Account>.Filter.Eq("Id", account.Id);

        if (!refreshToken.IsActive)
            throw new AppException("Invalid token");

        // revoke token and save
        revokeRefreshToken(refreshToken, ipAddress, "Revoked without replacement");
        var update = Builders<Account>.Update.Set(x => x.RefreshTokens, account.RefreshTokens);
        _accounts.UpdateOne(filter, update);
    }

    public void Register(RegisterRequest model, string origin) {
        // validate
        if (_accounts.Find(x => x.Email == model.Email).Any()) {
            //throw new AppException("Email adresi '" + model.Email + "' sistemde mevcut!");
            // send already registered error in email to prevent account enumeration
            sendAlreadyRegisteredEmail(model.Email, origin);
            return;
        }

        Account account = new Account();
        account.Adi = model.Adi;
        account.Soyadi = model.Soyadi;
        account.Email = model.Email;
        //! password ve confirmpassword için boş olamaz kısmı automapper da nasıl işliyor bakılacak
        account.Password = model.Password;
        // hash password
        account.PasswordHash = BCrypt.HashPassword(model.Password);
        account.AcceptTerms = model.AcceptTerms;
        account.Role = Role.User;
        account.VerificationToken = generateVerificationToken();
        account.Created = DateTime.UtcNow;
        account.RefreshTokens = new List<RefreshToken>();
        // save user
        _accounts.InsertOne(account);

        // send email
        sendVerificationEmail(account, origin);
    }

    public void VerifyEmail(string token) {
        var account = _accounts.Find(x => x.VerificationToken == token).SingleOrDefault();

        if (account == null)
            throw new AppException("Doğrulama başarısız oldu");

        account.Verified = DateTime.UtcNow;
        account.VerificationToken = null;

        var filter = Builders<Account>.Filter.Eq("Id", account.Id);
        var update = Builders<Account>.Update
            .Set(x => x.Verified, DateTime.UtcNow)
            .Set(x => x.VerificationToken, null);
        _accounts.UpdateOne(filter, update);
    }

    public void ForgotPassword(ForgotPasswordRequest model, string origin) {
        var account = _accounts.Find(x => x.Email == model.Email).SingleOrDefault();

        // always return ok response to prevent email enumeration
        if (account == null) return;

        // create reset token that expires after 1 day
        string resetToken = generateResetToken();
        account.ResetToken = resetToken;

        var filter = Builders<Account>.Filter.Eq("Id", account.Id);
        var update = Builders<Account>.Update
            .Set(x => x.ResetToken, resetToken)
            .Set(x => x.ResetTokenExpires, DateTime.UtcNow.AddDays(1));
        _accounts.UpdateOne(filter, update);

        // send email
        sendPasswordResetEmail(account, origin);
    }

    public void ValidateResetToken(ValidateResetTokenRequest model) {
        getAccountByResetToken(model.Token);
    }

    public void ResetPassword(ResetPasswordRequest model) {
        var account = getAccountByResetToken(model.Token);

        // update password and remove reset token
        account.PasswordHash = BCrypt.HashPassword(model.Password);
        account.PasswordReset = DateTime.UtcNow;
        account.ResetToken = null;
        account.ResetTokenExpires = null;

        var filter = Builders<Account>.Filter.Eq("Id", account.Id);
        _accounts.ReplaceOne(filter, account);
    }

    public IEnumerable<AccountResponse> GetAll() {
        var accounts = _accounts.Find(account => true).ToList();
        List<AccountResponse> ListAccountResponse = new List<AccountResponse>();

        foreach (var a in accounts) {
            ListAccountResponse.Add(new AccountResponse(a) {
                // Id = a.Id,
                // Adi = a.Adi,
                // Soyadi = a.Soyadi,
                // Email = a.Email,
                // Role = a.Role.ToString(),
                // Created = a.Created,
                // Updated = a.Updated,
                // IsVerified = a.IsVerified
            });
        }

        return ListAccountResponse;
    }

    public AccountResponse GetById(string id) {
        var account = getAccount(id);
        var result = new AccountResponse(account);
        return result;
    }

    public AccountResponse Create(CreateRequest model) {
        // validate
        if (_accounts.Find(x => x.Email == model.Email).Any())
            throw new AppException($"Email adresi '{model.Email}' sistemde mevcut!");

        Account account = new Account();
        account.Adi = model.Adi;
        account.Soyadi = model.Soyadi;
        account.Role = Role.User;
        account.Email = model.Email;
        //! password ve confirmpassword için boş olamaz kısmı automapper da nasıl işliyor bakılacak
        account.Password = model.Password;
        // hash password
        account.PasswordHash = BCrypt.HashPassword(model.Password);
        account.Created = DateTime.UtcNow;
        account.Verified = DateTime.UtcNow;
        // save user
        _accounts.InsertOne(account);

        return new AccountResponse(account);
    }

    public AccountResponse Update(string id, UpdateRequest model) {
        var account = getAccount(id);

        // validate
        if (model.Email != account.Email && _accounts.Find(x => x.Email == model.Email).Any())
            throw new AppException($"Email adresi '{model.Email}' sistemde mevcut!");

        // hash password if it was entered
        if (!string.IsNullOrEmpty(model.Password)) {
            //! password ve confirmpassword için boş olamaz kısmı automapper da nasıl işliyor bakılacak
            account.Password = model.Password;
            account.PasswordHash = BCrypt.HashPassword(model.Password);
        }

        account.Adi = model.Adi;
        account.Soyadi = model.Soyadi;
        account.Role = Enum.Parse<Role>(model.Role, false);
        account.Email = model.Email;
        account.Updated = DateTime.UtcNow;

        var filter = Builders<Account>.Filter.Eq("Id", id);
        _accounts.ReplaceOne(filter, account);

        return new AccountResponse(account);
    }

    public void Delete(string id) {
        var account = getAccount(id);
        var filter = Builders<Account>.Filter.Eq("Id", id);
        account.IsDisabled = true;
        account.PasswordHash = BCrypt.HashPassword(Guid.NewGuid().ToString());
        _accounts.ReplaceOne(filter, account);
    }

    public bool OwnsToken(string token, string id) {
        var account=getAccount(id);
        var result=account.RefreshTokens.Any(x=>x.Token==token);
        return result;




    }
    private Account getAccount(string id) {
        var account = _accounts.Find(x => x.Id == id).FirstOrDefault();
        if (account == null) throw new KeyNotFoundException("Kullanıcı bulunamadı");
        return account;
    }

    //! helper methods bu kısım silinecek
    private string generateJwtToken(Account account) {
        // generate token that is valid for 7 days
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
        var tokenDescriptor = new SecurityTokenDescriptor {
            Subject = new ClaimsIdentity(new[] { new Claim("id", account.Id) }),
            Expires = DateTime.UtcNow.AddMinutes(15),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    private Account getAccountByRefreshToken(string token) {
        var account = _accounts.Find(u => u.RefreshTokens.Any(t => t.Token == token)).SingleOrDefault();

        if (account == null)
            throw new AppException("Invalid token");

        return account;
    }

    private Account getAccountByResetToken(string token) {
        var account = _accounts.Find(u => u.ResetToken == token && u.ResetTokenExpires > DateTime.UtcNow).SingleOrDefault();
        if (account == null) throw new AppException("Invalid token");
        return account;
    }

    private string generateResetToken() {
        // token is a cryptographically strong random sequence of values
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(64));

        // ensure token is unique by checking against db
        var tokenIsUnique = _accounts.Find(x => x.ResetToken == token).Any();
        if (tokenIsUnique)
            return generateResetToken();

        return token;
    }

    private string generateVerificationToken() {
        // token is a cryptographically strong random sequence of values
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(64));

        // ensure token is unique by checking against db
        //! ilk yüklemede mongodb de account dokumanı yoksa kapatılmalı.
        var tokenIsUnique = _accounts.Find(x => x.VerificationToken == token).Any();

        if (tokenIsUnique)
            return generateVerificationToken();

        return token;
    }

    private RefreshToken rotateRefreshToken(RefreshToken refreshToken, string ipAddress) {
        var newRefreshToken = _jwtUtils.GenerateRefreshToken(ipAddress);
        revokeRefreshToken(refreshToken, ipAddress, "Replaced by new token", newRefreshToken.Token);
        return newRefreshToken;
    }

    private void removeOldRefreshTokens(Account account) {
        // remove old inactive refresh tokens from user based on TTL in app settings
        account.RefreshTokens.RemoveAll(x =>
            !x.IsActive &&
            x.Created.AddDays(_appSettings.RefreshTokenTTL) <= DateTime.UtcNow);
    }

    private void revokeDescendantRefreshTokens(RefreshToken refreshToken, Account account, string ipAddress, string reason) {
        // recursively traverse the refresh token chain and ensure all descendants are revoked
        if (!string.IsNullOrEmpty(refreshToken.ReplacedByToken)) {
            var childToken = account.RefreshTokens.SingleOrDefault(x => x.Token == refreshToken.ReplacedByToken);
            if (childToken.IsActive)
                revokeRefreshToken(childToken, ipAddress, reason);
            else
                revokeDescendantRefreshTokens(childToken, account, ipAddress, reason);
        }
    }

    private void revokeRefreshToken(RefreshToken token, string ipAddress, string reason = null, string replacedByToken = null) {
        token.Revoked = DateTime.UtcNow;
        token.RevokedByIp = ipAddress;
        token.ReasonRevoked = reason;
        token.ReplacedByToken = replacedByToken;
    }

    private void sendVerificationEmail(Account account, string origin) {
        string message;
        if (!string.IsNullOrEmpty(origin)) {
            // origin exists if request sent from browser single page app (e.g. Angular or React)
            // so send link to verify via single page app
            var verifyUrl = $"{origin}/account/verify-email?token={account.VerificationToken}";
            message = $@"<p>E-posta adresinizi doğrulamak için lütfen aşağıdaki bağlantıya tıklayın:</p>
                            <p><a href=""{verifyUrl}"">{verifyUrl}</a></p>";
        } else {
            // origin missing if request sent directly to api (e.g. from Postman)
            // so send instructions to verify directly with api
            message = $@"<p>Lütfen e-posta adresinizi doğrulamak için aşağıdaki api ile kodu kullanın <code>/accounts/verify-email</code> </p>
                            <p><code>{account.VerificationToken}</code></p>";
        }

        _emailService.Send(
            to: account.Email,
            subject: "Kayıt Doğrulama - E-postayı Doğrulayın",
            html: $@"<h4>E-posta doğrula</h4>
                        <p>Kaydolduğunuz için teşekkürler!</p>
                        {message}"
        );
    }

    private void sendAlreadyRegisteredEmail(string email, string origin) {
        string message;
        if (!string.IsNullOrEmpty(origin))
            message = $@"<p>Şifrenizi bilmiyorsanız lütfen <a href=""{origin}/account/forgot-password"">şifremi unuttum</a> sayfasını ziyaret edin.</p>";
        else
            message = "<p>Şifrenizi bilmiyorsanız, şifrenizi şu adresten sıfırlayabilirsiniz: <code>/accounts/forgot-password</code> </p>";

        _emailService.Send(
            to: email,
            subject: "Kayıt Doğrulama - E-posta zaten kayıtlı",
            html: $@"<h4>E-posta zaten kayıtlı</h4>
                        <p>E-postanız <strong>{email}</strong> zaten kayıtlı.</p>
                        {message}"
        );
    }

    private void sendPasswordResetEmail(Account account, string origin) {
        string message;
        if (!string.IsNullOrEmpty(origin)) {
            var resetUrl = $"{origin}/account/reset-password?token={account.ResetToken}";
            message = $@"<p>Lütfen şifrenizi sıfırlamak için aşağıdaki linke tıklayınız, link 1 gün süreyle geçerli olacaktır:</p>
                            <p><a href=""{resetUrl}"">{resetUrl}</a></p>";
        } else {
            message = $@"<p>Şifrenizi sıfırlamak için lütfen aşağıdaki api ile kodu kullanın. <code>/accounts/reset-password</code> </p>
                            <p><code>{account.ResetToken}</code></p>";
        }

        _emailService.Send(
            to: account.Email,
            subject: "Sign-up Verification API - Reset Password",
            html: $@"<h4>Reset Password Email</h4>
                        {message}"
        );
    }
}
