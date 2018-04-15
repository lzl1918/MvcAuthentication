using AuthenticationCore.Internals.Helpers;
using Microsoft.AspNetCore.Http;
using System;
using System.Security.Claims;

namespace AuthenticationCore.Internals
{
    internal interface IAuthenticationResultAccessor
    {
        IAuthenticationResult Result { get; set; }
        event EventHandler ResultUpdated;
    }
}
