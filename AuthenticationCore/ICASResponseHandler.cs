using Microsoft.AspNetCore.Http;
using System;
using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;

namespace AuthenticationCore
{

    public interface ICASResponseHandler
    {
        void Invoke(HttpContext httpContext, string message, string actionUrl, out string redirectUrl);
    }
}
