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
using webapiV2.Helpers;
using webapiV2.Models;
using webapiV2.Models.Users;

public interface IUserService
{
    AuthenticateResponse Authenticate(AuthenticateRequest model);
    IEnumerable<User> GetAll();
    User GetById(string id);
    void Register(User model);
    void Update(string id, User model);
    // void Register(RegisterRequest model);
    // void Update(string id, UpdateRequest model);
    void Delete(string id);
}

public class UserService : IUserService
{
    private readonly IMongoCollection<User> _users;
    private IJwtUtils _jwtUtils;

    // users hardcoded for simplicity, store in a db with hashed passwords in production applications
    // private List<User> _users = new List<User>
    // {
    //     new User { Id = "1", Adi = "Test", Soyadi = "User", Username = "test", Password = "test" }
    // };

    //private readonly AppSettings _appSettings;
    //IOptions<AppSettings> appSettings,
    public UserService(IOptions<DatabaseSettings> db, IJwtUtils jwtUtils)
    {
        //_appSettings = appSettings.Value;
        var mongoClient = new MongoClient(db.Value.ConnectionString);

        var mongoDatabase = mongoClient.GetDatabase(db.Value.DatabaseName);

        _users = mongoDatabase.GetCollection<User>("Users");
        _jwtUtils = jwtUtils;
    }

    public AuthenticateResponse Authenticate(AuthenticateRequest model)
    {
        var user = this._users.Find(x => x.Username == model.Username && x.Password == model.Password).SingleOrDefault();
        //_users.SingleOrDefault(x => x.Username == model.Username && x.Password == model.Password);
        // return null if user not found
        //if (user == null) return null;
        // validate
        if (user == null || !BCrypt.Verify(model.Password, user.PasswordHash))
            throw new AppException("Kullanıcı adı veya şifre yanlış");

        // authentication successful so generate jwt token
        var token = _jwtUtils.GenerateToken(user);
        return new AuthenticateResponse(user, token);
        // var response = AuthenticateResponse(user);
        // response.Token =(user);
        // return response;
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
}