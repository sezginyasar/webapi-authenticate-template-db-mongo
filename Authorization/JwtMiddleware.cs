namespace webapiV2.Authorization;

using Microsoft.Extensions.Options;
using webapiV2.Helpers;
using webapiV2.Services;

public class JwtMiddleware {
    private readonly RequestDelegate _next;
    private readonly AppSettings _appSettings;

    public JwtMiddleware(RequestDelegate next, IOptions<AppSettings> appSettings) {
        _next = next;
        _appSettings = appSettings.Value;
    }

    public async Task Invoke(HttpContext context, IAccountService accountService, IJwtUtils jwtUtils) {
        var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
        var accountId = jwtUtils.ValidateJwtToken(token);
        if (accountId != null) {
            // attach account to context on successful jwt validation
            context.Items["Account"] = accountService.GetById(accountId);
        }

        await _next(context);
    }
}