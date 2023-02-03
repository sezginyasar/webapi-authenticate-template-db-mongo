namespace webapiV2.Controllers;

using Microsoft.AspNetCore.Mvc;
using webapiV2.Entities;
using webapiV2.Models.Accounts;

[Controller]
public abstract class BaseController : ControllerBase
{
    // returns the current authenticated account (null if not logged in)
    
    //public Account Account => (Account)HttpContext.Items["Account"];
    public AccountResponse Account => (AccountResponse)HttpContext.Items["Account"];

    //var account = (AccountResponse)context.HttpContext.Items["Account"];
        // var account = new Account();
        // account.Id = ar.Id;
        // account.Adi = ar.Adi;
        // account.Soyadi = ar.Soyadi;
        // account.Email=ar.Email;
        // account.Role=Enum.Parse<Role>(ar.Role,false);
        // account.Created=ar.Created;
        // account.Updated=ar.Updated;
        //account.IsVerified=ar.IsVerified;
}