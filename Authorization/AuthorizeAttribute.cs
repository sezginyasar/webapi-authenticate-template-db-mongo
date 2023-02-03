namespace webapiV2.Authorization;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using webapiV2.Entities;
using webapiV2.Models.Accounts;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class AuthorizeAttribute : Attribute, IAuthorizationFilter {

    private readonly IList<Role> _roles;

    public AuthorizeAttribute(params Role[] roles) {
        _roles = roles ?? new Role[] { };
    }
    public void OnAuthorization(AuthorizationFilterContext context) {
        // skip authorization if action is decorated with [AllowAnonymous] attribute
        var allowAnonymous = context.ActionDescriptor.EndpointMetadata.OfType<AllowAnonymousAttribute>().Any();
        if (allowAnonymous)
            return;

        // authorization (Account) 
        //var account =(Account)context.HttpContext.Items["Account"];
        var account = (AccountResponse)context.HttpContext.Items["Account"];
        // var account = new Account();
        // account.Id = ar.Id;
        // account.Adi = ar.Adi;
        // account.Soyadi = ar.Soyadi;
        // account.Email=ar.Email;
        // account.Role=Enum.Parse<Role>(ar.Role,false);
        // account.Created=ar.Created;
        // account.Updated=ar.Updated;
        //account.IsVerified=ar.IsVerified;

        if (account == null || (_roles.Any() && !_roles.Contains(account.Role))) {
            // not logged in or role not authorized
            context.Result = new JsonResult(new { message = "Unauthorized" }) { StatusCode = StatusCodes.Status401Unauthorized };
        }
        // var user = (User)context.HttpContext.Items["User"];
        // if (user == null)
        //     context.Result = new JsonResult(new { message = "Unauthorized" }) { StatusCode = StatusCodes.Status401Unauthorized };
    }
}