﻿using AuthenticationCore.Internals;
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
    public class CustomHandlerAttribute : Attribute
    {
        internal Type Handler { get; }
        public CustomHandlerAttribute(Type handler)
        {
            Handler = handler;
        }

        internal IActionResult Execute(HttpContext httpContext, AuthenticationPolicy policy, Type[] customAuthenticators)
        {
            return AuthenticationHelper.ExecuteHandler(Handler, httpContext, policy, customAuthenticators);
        }
    }
}