using Microsoft.AspNetCore.Http;
using System;
using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Mvc.RazorPages.Internal;

namespace AuthenticationCore
{

    internal sealed class DefaultCASResponseHandler : ICASResponseHandler
    {
        public IUser Invoke(HttpContext httpContext, string message, string actionUrl, out string redirectUrl)
        {
            ICASOption option = httpContext.RequestServices.GetService<ICASOption>();
            string[] res = message.Split('\n');
            if (res[0] == "yes")
            {
                httpContext.Session.SetString(option.SessionName, res[1]);
                redirectUrl = actionUrl;
                return null;
            }
            else
            {
                httpContext.Session.Remove(option.SessionName);
                redirectUrl = null;
                return null;
            }
        }
    }
}
