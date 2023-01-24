namespace webapiV2.Services;

using BCrypt.Net;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Bson;
using MongoDB.Driver;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using webapiV2.Database;
using webapiV2.Entities;
using webapiV2.Authorization;
using webapiV2.Models;
using webapiV2.Models.Users;
using webapiV2.Helpers;

public interface IUserService
{
    AuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress);
    AuthenticateResponse RefreshToken(string token, string ipAddress);
    void RevokeToken(string token, string ipAddress);
    IEnumerable<User> GetAll();
    User GetById(string id);
    void Register(User model);
    void Update(string id, User model);
    //! Her işlem için modeli ayırmak gerekiyor.
    // void Register(RegisterRequest model);
    // void Update(string id, UpdateRequest model);
    void Delete(string id);
}

public class UserService : IUserService
{
    private readonly IMongoCollection<User> _users;
    private IJwtUtils _jwtUtils;
    private readonly AppSettings _appSettings;

    // users hardcoded for simplicity, store in a db with hashed passwords in production applications
    // private List<User> _users = new List<User>
    // {
    //     new User { Id = "1", Adi = "Test", Soyadi = "User", Username = "test", Password = "test" }
    // };

    //private readonly AppSettings _appSettings;
    //IOptions<AppSettings> appSettings,
    public UserService(IOptions<DatabaseSettings> db, IJwtUtils jwtUtils, IOptions<AppSettings> appSettings)
    {
        var mongoClient = new MongoClient(db.Value.ConnectionString);
        var mongoDatabase = mongoClient.GetDatabase(db.Value.DatabaseName);

        _users = mongoDatabase.GetCollection<User>("Users");
        _jwtUtils = jwtUtils;
        _appSettings = appSettings.Value;
    }

    public AuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress)
    {
        // var user = this._users.Find(x => x.Username == model.Username && x.Password == model.Password).SingleOrDefault();
        var user = this._users.Find(x => x.Username == model.Username).SingleOrDefault();
        //_users.SingleOrDefault(x => x.Username == model.Username && x.Password == model.Password);
        // return null if user not found
        //if (user == null) return null;
        Console.WriteLine(user.Password);
        // validate
        if (user == null || !BCrypt.Verify(model.Password, user.PasswordHash))
            throw new AppException("Kullanıcı adı veya şifre yanlış");

        // authentication successful so generate jwt token and refresh tokens
        var jwtToken = _jwtUtils.GenerateJwtToken(user);
        var refreshToken = _jwtUtils.GenerateRefreshToken(ipAddress);
        var filter = Builders<User>.Filter.Eq("Id", user.Id);
        
        var push = Builders<User>.Update.Push("RefreshTokens", refreshToken);
        _users.UpdateOne(filter, push);
        //user.RefreshTokens.Add(refreshToken);

        // remove old refresh tokens from user
        removeOldRefreshTokens(user);

        return new AuthenticateResponse(user, jwtToken, refreshToken.Token);
        // var response = AuthenticateResponse(user);
        // response.Token =(user);
        // return response;
    }

    public AuthenticateResponse RefreshToken(string token, string ipAddress)
    {
        var user = getUserByRefreshToken(token);
        var refreshToken = user.RefreshTokens.Single(x => x.Token == token);
        var filter = Builders<User>.Filter.Eq("Id", user.Id);

        if (refreshToken.IsRevoked)
        {
            // revoke all descendant tokens in case this token has been compromised
            revokeDescendantRefreshTokens(refreshToken, user, ipAddress, $"Attempted reuse of revoked ancestor token: {token}");
            var update = Builders<User>.Update.Set(x => x.RefreshTokens, user.RefreshTokens);
            _users.UpdateOne(filter, update);
            // _context.Update(user);
            // _context.SaveChanges();
        }

        if (!refreshToken.IsActive)
            throw new AppException("Invalid token");

        // replace old refresh token with a new one (rotate token)
        var newRefreshToken = rotateRefreshToken(refreshToken, ipAddress);
        user.RefreshTokens.Add(newRefreshToken);

        // remove old refresh tokens from user
        removeOldRefreshTokens(user);

        // save changes to db
        var push = Builders<User>.Update.Push("RefreshTokens", user.RefreshTokens);
        _users.UpdateOne(filter, push);
        // _context.Update(user);
        // _context.SaveChanges();

        // generate new jwt
        var jwtToken = _jwtUtils.GenerateJwtToken(user);

        return new AuthenticateResponse(user, jwtToken, newRefreshToken.Token);
    }

    public void RevokeToken(string token, string ipAddress)
    {
        var user = getUserByRefreshToken(token);
        var refreshToken = user.RefreshTokens.Single(x => x.Token == token);
        var filter = Builders<User>.Filter.Eq("Id", user.Id);

        if (!refreshToken.IsActive)
            throw new AppException("Invalid token");

        // revoke token and save
        revokeRefreshToken(refreshToken, ipAddress, "Revoked without replacement");
        var update = Builders<User>.Update.Set(x => x.RefreshTokens, user.RefreshTokens);
        _users.UpdateOne(filter, update);
        // _context.Update(user);
        // _context.SaveChanges();
    }

    public IEnumerable<User> GetAll()
    {
        return _users.Find(user => true).ToList();
        // return _users;
    }

    public User GetById(string id)
    {
        return getUser(id);
        // return _users.FirstOrDefault(x => x.Id == id);
    }

    public void Register(User model)
    {
        //Console.WriteLine(model.Password);
        // validate
        if (_users.Find(x => x.Username == model.Username).Any())
            throw new AppException("Kullanıcı Adı '" + model.Username + "' sistemde mevcut!");

        // map model to new user object
        //var user = _mapper.Map<User>(model);

        // hash password
        model.PasswordHash = BCrypt.HashPassword(model.Password);
        List<RefreshToken> rt= new List<RefreshToken>();
        //rt.Add(new RefreshToken(){});
        
        model.RefreshTokens = rt;



        // save user
        _users.InsertOne(model);
    }

    public void Update(string id, User model)
    {
        var user = getUser(id);

        // validate
        if (model.Username != user.Username && _users.Find(x => x.Username == model.Username).Any())
            throw new AppException("Kullanıcı Adı '" + model.Username + "' sistemde mevcut!");

        // hash password if it was entered
        if (!string.IsNullOrEmpty(model.Password))
            user.PasswordHash = BCrypt.HashPassword(model.Password);

        // copy model to user and save
        //_mapper.Map(model, user);
        var filter = Builders<User>.Filter.Eq("Id", id);
        _users.ReplaceOne(filter, model);
    }

    public void Delete(string id)
    {
        //! burasını daha sonra kullanıcıyı tamamen silmek değilde pasife getirmek için kodlanmalı yani update işlemi
        //var user = getUser(id);
        var filter = Builders<User>.Filter.Eq("Id", id);
        _users.DeleteOne(filter);
    }


    private User getUser(string id)
    {
        var user = _users.Find(x => x.Id == id).FirstOrDefault();
        if (user == null) throw new KeyNotFoundException("Kullanıcı bulunamadı");
        return user;
    }

    //! helper methods bu kısım silinecek
    private string generateJwtToken(User user)
    {
        // generate token that is valid for 7 days
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes("_appSettings.JwtKey");
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[] { new Claim("id", user.Id) }),
            Expires = DateTime.UtcNow.AddDays(7),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    private User getUserByRefreshToken(string token)
    {
        //_context.Users.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));
        var user = _users.Find(u => u.RefreshTokens.Any(t => t.Token == token)).SingleOrDefault();

        if (user == null)
            throw new AppException("Invalid token");

        return user;
    }

    private RefreshToken rotateRefreshToken(RefreshToken refreshToken, string ipAddress)
    {
        var newRefreshToken = _jwtUtils.GenerateRefreshToken(ipAddress);
        revokeRefreshToken(refreshToken, ipAddress, "Replaced by new token", newRefreshToken.Token);
        return newRefreshToken;
    }

    private void removeOldRefreshTokens(User user)
    {
        // remove old inactive refresh tokens from user based on TTL in app settings
        user.RefreshTokens.RemoveAll(x =>
            !x.IsActive &&
            x.Created.AddDays(_appSettings.RefreshTokenTTL) <= DateTime.UtcNow);
    }

    private void revokeDescendantRefreshTokens(RefreshToken refreshToken, User user, string ipAddress, string reason)
    {
        // recursively traverse the refresh token chain and ensure all descendants are revoked
        if (!string.IsNullOrEmpty(refreshToken.ReplacedByToken))
        {
            var childToken = user.RefreshTokens.SingleOrDefault(x => x.Token == refreshToken.ReplacedByToken);
            if (childToken.IsActive)
                revokeRefreshToken(childToken, ipAddress, reason);
            else
                revokeDescendantRefreshTokens(childToken, user, ipAddress, reason);
        }
    }

    private void revokeRefreshToken(RefreshToken token, string ipAddress, string reason = null, string replacedByToken = null)
    {
        token.Revoked = DateTime.UtcNow;
        token.RevokedByIp = ipAddress;
        token.ReasonRevoked = reason;
        token.ReplacedByToken = replacedByToken;
    }
}