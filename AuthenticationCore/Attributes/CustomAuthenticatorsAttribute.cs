using AuthenticationCore.Internals;
using AuthenticationCore.Internals.Helpers;
using AuthenticationCore.Internals.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Text;

namespace AuthenticationCore
{
    public enum CustomAuthenticatorExecutionPolicy
    {
        BeforeCAS, AfterCAS
    }

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
    public class CustomAuthenticatorsAttribute : Attribute
    {
        private readonly Type[] authenticators;
        internal CustomAuthenticatorExecutionPolicy ExecutionPolicy { get; }
        internal Type[] Authenticators => authenticators;

        public CustomAuthenticatorsAttribute(CustomAuthenticatorExecutionPolicy policy = CustomAuthenticatorExecutionPolicy.BeforeCAS, params Type[] authenticators)
        {
            ExecutionPolicy = policy;
            this.authenticators = authenticators;
        }

        internal AuthenticationInternalResult Authenticate(HttpContext httpContext)
        {
            if (authenticators.Length <= 0)
                return null;

            IAuthenticatorMethodCache cache = httpContext.RequestServices.GetRequiredService<IAuthenticatorMethodCache>();
            foreach (Type authenticator in authenticators)
            {
                if (AuthenticationHelper.IsValidAuthenticator(cache, authenticator, out AuthenticatorMetadata metadata))
                {
                    AuthenticationInternalResult result = AuthenticationHelper.ExecuteAuthenticator(httpContext, metadata);
                    if (result != null)
                        return result;
                }

            }
            return null;
        }
    }
}
