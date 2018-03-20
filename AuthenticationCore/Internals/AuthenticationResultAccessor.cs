using AuthenticationCore.Internals.Helpers;
using Microsoft.AspNetCore.Http;
using System;
using System.Security.Claims;

namespace AuthenticationCore.Internals
{
    internal sealed class AuthenticationResultAccessor : IAuthenticationResultAccessor
    {
        private readonly IHttpContextAccessor httpContextAccessor;
        public event EventHandler ResultUpdated;

        public IAuthenticationResult Result
        {
            get => AuthenticationHelper.ReadAuthenticationResult(httpContextAccessor.HttpContext);
            set
            {
                AuthenticationHelper.SaveAuthenticationResult(httpContextAccessor.HttpContext, value);
                ResultUpdated?.Invoke(this, new EventArgs());
            }
        }

        public AuthenticationResultAccessor(IHttpContextAccessor httpContextAccessor)
        {
            this.httpContextAccessor = httpContextAccessor;
        }
    }
}
