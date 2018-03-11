using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using AuthenticationCore.Internals.Helpers;
using AuthenticationCore.Internals.ResponseResults;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationCore.Internals
{
    internal sealed class AuthenticationService : IAuthenticationService
    {
        private readonly IHttpContextAccessor httpContextAccessor;
        private readonly ICASOption option;

        public AuthenticationService(IHttpContextAccessor httpContextAccessor, ICASOption option)
        {
            this.httpContextAccessor = httpContextAccessor;
            this.option = option;
        }

        public Task<IAuthenticationResult> AuthenticateAsync(IEnumerable<Type> authenticators, bool saveResult)
        {
            return Task.Run<IAuthenticationResult>(() =>
            {
                HttpContext httpContext = httpContextAccessor.HttpContext;
                AuthenticationInternalResult result = null;
                foreach (Type authenticator in authenticators)
                {
                    if (AuthenticationHelper.IsValidAuthenticator(authenticator, out MethodInfo authenticateMethod))
                    {
                        result = AuthenticationHelper.ExecuteAuthenticator(httpContext, new AuthenticatorMetadata(authenticator, authenticateMethod));
                        if (result != null && result.KeepUnauthenticated == false && result.User != null)
                        {
                            IAuthenticationResult authentication = AuthenticationResult.CAS(result.User);
                            if (saveResult)
                            {
                                AuthenticationHelper.SaveAuthenticationResult(httpContext, authentication);
                            }
                            return authentication;
                        }
                    }
                }
                return AuthenticationResult.Unauthenticated();
            });
        }

        public Task<IAuthenticationResult> CASAsync(bool saveResult)
        {
            return Task.Run<IAuthenticationResult>(() =>
            {
                HttpContext httpContext = httpContextAccessor.HttpContext;
                AuthenticationInternalResult result = AuthenticationHelper.ExecuteCAS(httpContext);

                if (result != null && result.KeepUnauthenticated == false && result.User != null)
                {
                    IAuthenticationResult authentication = AuthenticationResult.CAS(result.User);
                    if (saveResult)
                    {
                        AuthenticationHelper.SaveAuthenticationResult(httpContext, authentication);
                    }
                    return authentication;
                }
                return AuthenticationResult.Unauthenticated();
            });
        }

        public IActionResult CreateRedirectCASResult()
        {
            return new HttpCASRedirectResult();
        }
    }
}
