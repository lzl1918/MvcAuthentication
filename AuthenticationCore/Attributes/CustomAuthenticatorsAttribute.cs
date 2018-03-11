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
    public enum CustomAuthenticatorExecutionPolicy
    {
        BeforeCAS, AfterCAS
    }

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
    public class CustomAuthenticatorsAttribute : Attribute
    {
        internal CustomAuthenticatorExecutionPolicy ExecutionPolicy { get; }
        internal AuthenticatorMetadata[] Authenticators { get; }

        public CustomAuthenticatorsAttribute(CustomAuthenticatorExecutionPolicy policy = CustomAuthenticatorExecutionPolicy.BeforeCAS, params Type[] authenticators)
        {
            ExecutionPolicy = policy;
            List<AuthenticatorMetadata> metadata = new List<AuthenticatorMetadata>();
            foreach (Type authenticator in authenticators)
            {
                if (AuthenticationHelper.IsValidAuthenticator(authenticator, out MethodInfo authenticateMethod))
                {
                    metadata.Add(new AuthenticatorMetadata(authenticator, authenticateMethod));
                }
            }
            Authenticators = metadata.ToArray();
        }

        internal AuthenticationInternalResult Authenticate(HttpContext httpContext)
        {
            if (Authenticators.Length <= 0)
                return null;
            foreach (AuthenticatorMetadata authenticator in Authenticators)
            {
                AuthenticationInternalResult result = AuthenticationHelper.ExecuteAuthenticator(httpContext, authenticator);
                if (result != null)
                    return result;
            }
            return null;
        }
    }
}
