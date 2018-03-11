using AuthenticationCore.Internals.Helpers;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace AuthenticationCore.Internals
{
    internal sealed class AuthenticationResultAccessor : IAuthenticationResultAccessor
    {
        private readonly IHttpContextAccessor httpContextAccessor;
        private IAuthenticationResult result;
        public IAuthenticationResult Result => result ?? (result = AuthenticationHelper.ReadAuthenticationResult(httpContextAccessor.HttpContext));

        public AuthenticationResultAccessor(IHttpContextAccessor httpContextAccessor)
        {
            this.httpContextAccessor = httpContextAccessor;
        }
    }
}
