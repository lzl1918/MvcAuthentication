using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using AuthenticationCore.Internals.Helpers;
using AuthenticationCore.Internals.ResponseResults;
using AuthenticationCore.Internals.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;

namespace AuthenticationCore.Internals
{
    internal sealed class AuthenticationService : IAuthenticationService
    {
        private readonly IHttpContextAccessor httpContextAccessor;
        private readonly ICASOption option;
        private readonly IAuthenticationResultAccessor accessor;

        public AuthenticationService(IHttpContextAccessor httpContextAccessor, ICASOption option, IAuthenticationResultAccessor accessor)
        {
            this.httpContextAccessor = httpContextAccessor;
            this.option = option;
            this.accessor = accessor;
        }

        public Task<IAuthenticationResult> AuthenticateAsync(IEnumerable<Type> authenticators, bool saveResult)
        {
            return Task.Run<IAuthenticationResult>(() =>
            {
                HttpContext httpContext = httpContextAccessor.HttpContext;
                AuthenticationInternalResult result = null;
                foreach (Type authenticator in authenticators)
                {
                    if (AuthenticationHelper.IsValidAuthenticator(httpContext.RequestServices.GetRequiredService<IAuthenticatorMethodCache>(), authenticator, out AuthenticatorMetadata authenticateMethod))
                    {
                        result = AuthenticationHelper.ExecuteAuthenticator(httpContext, authenticateMethod);
                        if (result != null && result.KeepUnauthenticated == false && result.User != null)
                        {
                            IAuthenticationResult authentication = AuthenticationResult.CAS(result.User);
                            if (saveResult)
                            {
                                accessor.Result = authentication;
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
                        accessor.Result = authentication;
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

        public IActionResult CreateRedirectLogoutResult(string target)
        {
            return new HttpCASLogoutRedirectResult(target);
        }
        public IActionResult CreateRedirectLogoutResult()
        {
            return new HttpCASLogoutRedirectResult();
        }

        public void RemoveCASSession()
        {
            HttpContext context = httpContextAccessor.HttpContext;
            IServiceProvider services = context.RequestServices;
            ICASOption option = services.GetRequiredService<ICASOption>();
            context.Session.Remove(option.SessionName);
        }
    }
}
