namespace webapiV2.Controllers;

using Microsoft.AspNetCore.Mvc;
using webapiV2.Authorization;
// using Microsoft.Extensions.Options;
using webapiV2.Entities;
// using webapiV2.Helpers;
using webapiV2.Models;
using webapiV2.Models.Users;
using webapiV2.Services;

[Authorize]
[ApiController]
[Route("[controller]")]
public class UsersController : ControllerBase
{
    private IUserService _userService;

    public UsersController(IUserService userService)
    {
        _userService = userService;
    }

    [AllowAnonymous]
    [HttpPost("authenticate")]
    public IActionResult Authenticate(AuthenticateRequest model)
    {
        var response = _userService.Authenticate(model, ipAddress());
        setTokenCookie(response.RefreshToken);
        // if (response == null)
        //     return BadRequest(new { message = "Kullanıcı adı veya şifre yanlış!" });

        return Ok(response);
    }

    [AllowAnonymous]
    [HttpPost("refresh-token")]
    public IActionResult RefreshToken()
    {
        var refreshToken = Request.Cookies["refreshToken"];
        var response = _userService.RefreshToken(refreshToken, ipAddress());
        setTokenCookie(response.RefreshToken);
        return Ok(response);
    }

    [HttpPost("revoke-token")]
    public IActionResult RevokeToken(RevokeTokenRequest model)
    {
        // accept refresh token in request body or cookie
        var token = model.Token ?? Request.Cookies["refreshToken"];

        if (string.IsNullOrEmpty(token))
            return BadRequest(new { message = "Token is required" });

        _userService.RevokeToken(token, ipAddress());
        return Ok(new { message = "Token revoked" });
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

    [HttpGet("{id}/refresh-tokens")]
    public IActionResult GetRefreshTokens(string id)
    {
        var user = _userService.GetById(id);
        return Ok(user.RefreshTokens);
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

    // helper methods
    private void setTokenCookie(string token)
    {
        // append cookie with refresh token to the http response
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Expires = DateTime.UtcNow.AddDays(7)
        };
        Response.Cookies.Append("refreshToken", token, cookieOptions);
    }

    private string ipAddress()
    {
        // get source ip address for the current request
        if (Request.Headers.ContainsKey("X-Forwarded-For"))
            return Request.Headers["X-Forwarded-For"];
        else
            return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
    }
}