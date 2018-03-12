﻿using Microsoft.AspNetCore.Http;
using System;
using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;

namespace AuthenticationCore
{

    internal sealed class DefaultCASResponseHandler : ICASResponseHandler
    {
        public void Invoke(HttpContext httpContext, string message, string actionUrl, out string redirectUrl)
        {
            ICASOption option = httpContext.RequestServices.GetService<ICASOption>();
            string[] res = message.Split('\n');
            if (res[0] == "yes")
            {
                httpContext.Session.SetString(option.SessionName, res[1]);
                redirectUrl = actionUrl;
            }
            else
            {
                httpContext.Session.Remove(option.SessionName);
                redirectUrl = null;
            }
        }
    }
}