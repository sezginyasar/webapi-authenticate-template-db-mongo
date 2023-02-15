namespace webapiV2.Controllers;

using Microsoft.AspNetCore.Mvc;
using webapiV2.Authorization;
// using Microsoft.Extensions.Options;
using webapiV2.Entities;
// using webapiV2.Helpers;
using webapiV2.Models;
using webapiV2.Models.Accounts;
using webapiV2.Services;

[Authorize]
[ApiController]
[Route("[controller]")]
public class AccountsController : BaseController {
    private readonly IAccountService _accountService;
    private readonly ILogger<AccountsController> _logger;

    public AccountsController(IAccountService accountService, ILogger<AccountsController> lg) {
        _accountService = accountService;
        _logger = lg;
    }

    [AllowAnonymous]
    [HttpPost("authenticate")]
    public ActionResult<AuthenticateResponse> Authenticate(AuthenticateRequest model) {
        //_logger.LogInformation
        Console.WriteLine("Request content type:{0}", Request.ContentType);
        var response = _accountService.Authenticate(model, ipAddress());
        setTokenCookie(response.RefreshToken);
        Console.WriteLine("refresh token cookie", response.RefreshToken);
        return Ok(response);
    }

    [AllowAnonymous]
    [HttpPost("refresh-token")]
    public ActionResult<AuthenticateResponse> RefreshToken() {
        var refreshToken = Request.Cookies["refreshToken"];
        var response = _accountService.RefreshToken(refreshToken, ipAddress());
        setTokenCookie(response.RefreshToken);
        Console.WriteLine("refresh token cookie", response.RefreshToken);
        return Ok(response);
    }

    [HttpPost("revoke-token")]
    public IActionResult RevokeToken(RevokeTokenRequest model) {
        // kullanıcıyı kapatmak sistemden atmak için yada 
        // kullanıcının kedi açık hesaplarını kapatması için kullanılır
        // accept refresh token in request body or cookie
        var token = model.Token ?? Request.Cookies["refreshToken"];

        if (string.IsNullOrEmpty(token))
            return BadRequest(new { message = "Token is required" });

        // users can revoke their own tokens and admins can revoke any tokens
        // iptal edilen tokenı iptal eden kişi ADMIN rolündeyse herkesinkini iptal edebilir. role USER ise sadece kendisinin token larını iptal edebilir.
        // OwnsToken gelen token bilgisini kendi refresh tokenların arasında varmı diye kontrol ediyor.
        bool OwnsToken = _accountService.OwnsToken(token, Account.Id); //!Account.OwnsToken(token)

        if (!OwnsToken && Account.Role != Role.Admin)
            return Unauthorized(new { message = "Unauthorized" });

        _accountService.RevokeToken(token, ipAddress());
        return Ok(new { message = "Token revoked" });
    }

    //! daha sonra AllowAnonymous kaldırılacak. Bizim sistemlerde kayıtlı bir kullanıcı hesap oluşturabilir.
    [AllowAnonymous]
    [HttpPost("register")]
    public IActionResult Register(RegisterRequest model) {
        //Console.WriteLine(model);
        _accountService.Register(model, Request.Headers["origin"]);
        return Ok(new { message = "Kayıt Başarılı, lütfen doğrulama talimatları için e-postanızı kontrol edin" });
    }

    [AllowAnonymous]
    [HttpPost("verify-email")]
    public IActionResult VerifyEmail(VerifyEmailRequest model) {
        _accountService.VerifyEmail(model.Token);
        return Ok(new { message = "Doğrulama başarılı, şimdi giriş yapabilirsiniz" });
    }

    [AllowAnonymous]
    [HttpPost("forgot-password")]
    public IActionResult ForgotPassword(ForgotPasswordRequest model) {
        _accountService.ForgotPassword(model, Request.Headers["origin"]);
        return Ok(new { message = "Parola sıfırlama talimatları için lütfen e-postanızı kontrol edin" });
    }

    [AllowAnonymous]
    [HttpPost("validate-reset-token")]
    public IActionResult ValidateResetToken(ValidateResetTokenRequest model) {
        _accountService.ValidateResetToken(model);
        return Ok(new { message = "Token is valid" });
    }

    [AllowAnonymous]
    [HttpPost("reset-password")]
    public IActionResult ResetPassword(ResetPasswordRequest model) {
        _accountService.ResetPassword(model);
        return Ok(new { message = "Parola sıfırlama başarılı, şimdi giriş yapabilirsiniz" });
    }

    [Authorize(Role.Admin)]
    [HttpGet]
    public ActionResult<IEnumerable<AccountResponse>> GetAll() {
        var accounts = _accountService.GetAll();
        return Ok(accounts);
    }

    [HttpGet("{id}")]
    public ActionResult<AccountResponse> GetById(string id) {
        // users can get their own account and admins can get any account
        if (id != Account.Id && Account.Role != Role.Admin)
            return Unauthorized(new { message = "Unauthorized" });

        var account = _accountService.GetById(id);
        return Ok(account);
    }

    //! KONTROL EDİLECEK
    // [HttpGet("{id}/refresh-tokens")]
    // public IActionResult GetRefreshTokens(string id) {
    //     var user = _userService.GetById(id);
    //     return Ok(user.RefreshTokens);
    // }

    [Authorize(Role.Admin)]
    [HttpPost]
    public ActionResult<AccountResponse> Create(CreateRequest model) {
        var account = _accountService.Create(model);
        return Ok(account);
    }

    [HttpPut("{id}")]
    public ActionResult<AccountResponse> Update(string id, UpdateRequest model) {
        // users can update their own account and admins can update any account
        if (id != Account.Id && Account.Role != Role.Admin)
            return Unauthorized(new { message = "Unauthorized" });

        // only admins can update role
        if (Account.Role != Role.Admin)
            model.Role = null;

        var account = _accountService.Update(id, model);
        return Ok(account);

        // _userService.Update(id, model);
        // return Ok(new { message = "Kullanıcı güncelleme başarılı" });
    }

    [HttpDelete("{id}")]
    public IActionResult Delete(string id) {

        // users can delete their own account and admins can delete any account
        if (id != Account.Id && Account.Role != Role.Admin)
            return Unauthorized(new { message = "Unauthorized" });

        _accountService.Delete(id);
        return Ok(new { message = "Kullanıcı pasif duruma getirildi." });
    }

    // helper methods
    private void setTokenCookie(string token) {
        // append cookie with refresh token to the http response
        var cookieOptions = new CookieOptions {
            HttpOnly = true,
            Expires = DateTime.UtcNow.AddDays(5),
            Domain="localhost",
            SameSite = SameSiteMode.Lax,
            //Secure = false
        };
        Response.Cookies.Append("refreshToken", token, cookieOptions);
    }

    private string ipAddress() {
        // get source ip address for the current request
        if (Request.Headers.ContainsKey("X-Forwarded-For"))
            return Request.Headers["X-Forwarded-For"];
        else
            return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
    }
}