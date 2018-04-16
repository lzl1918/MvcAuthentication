using Microsoft.AspNetCore.Http;
using System;
using System.Security.Claims;

namespace AuthenticationCore
{
    public interface ICASOption
    {
        string RedirectUrl { get; }
        string ValidateUrl { get; }
        string LogoutUrl { get; }

        string SessionName { get; }

        string ResponseAccept { get; }
        Type ResponseHandler { get; }
    }
}
