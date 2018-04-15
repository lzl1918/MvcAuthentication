using AuthenticationCore.Internals;
using AuthenticationCore.Internals.Helpers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Text;

namespace AuthenticationCore
{

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
    public class AuthenticationFailedHandlerAttribute : Attribute
    {
        internal object[] ConstructParameters { get; }
        internal Type Handler { get; }

        public AuthenticationFailedHandlerAttribute(Type handler, params object[] constructParameters)
        {
            Handler = handler;
            ConstructParameters = constructParameters;
        }

        internal IActionResult Execute(HttpContext httpContext, AuthenticationPolicy policy, Type[] customAuthenticators)
        {
            return AuthenticationHelper.ExecuteHandler(Handler, ConstructParameters, httpContext, policy, customAuthenticators);
        }
    }
}
