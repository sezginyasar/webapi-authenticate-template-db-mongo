namespace webapiV2.Controllers;

using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using webapiV2.Entities;
using webapiV2.Helpers;
using webapiV2.Models;
using webapiV2.Models.Users;
using webapiV2.Services;

[Authorize]
[ApiController]
[Route("[controller]")]
public class UsersController : ControllerBase
{
    private IUserService _userService;
    private readonly AppSettings _appSettings;

    public UsersController(IUserService userService, IOptions<AppSettings> appSettings)
    {
        _userService = userService;
        _appSettings = appSettings.Value;
    }

    [AllowAnonymous]
    [HttpPost("authenticate")]
    public IActionResult Authenticate(AuthenticateRequest model)
    {
        var response = _userService.Authenticate(model);

        if (response == null)
            return BadRequest(new { message = "Kullanıcı adı veya şifre yanlış!" });

        return Ok(response);
    }

    //! daha sonra AllowAnonymous kaldırılacak. Bizim sistemlerde kayıtlı bir kullanıcı hesap oluşturabilir.
    [AllowAnonymous]
    [HttpPost("register")]
    public IActionResult Register(User model)
    {
        //Console.WriteLine(model);
        _userService.Register(model);
        return Ok(new { message = "Kayıt Başarılı" });
    }

    [HttpGet]
    public IActionResult GetAll()
    {
        var users = _userService.GetAll();
        return Ok(users);
    }
    [HttpGet("{id}")]
    public IActionResult GetById(string id)
    {
        var user = _userService.GetById(id);
        return Ok(user);
    }

    [HttpPut("{id}")]
    public IActionResult Update(string id, User model)
    {
        _userService.Update(id, model);
        return Ok(new { message = "Kullanıcı güncelleme başarılı" });
    }

    [HttpDelete("{id}")]
    public IActionResult Delete(string id)
    {
        _userService.Delete(id);
        return Ok(new { message = "Kullanıcı pasif duruma getirildi." });
    }
}