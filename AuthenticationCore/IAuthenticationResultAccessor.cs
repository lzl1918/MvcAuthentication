using AuthenticationCore.Internals.Helpers;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace AuthenticationCore
{

    public interface IAuthenticationResultAccessor
    {
        IAuthenticationResult Result { get; }
    }
}
