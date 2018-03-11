using System;
using System.Security.Claims;

namespace AuthenticationCore
{
    public interface ICASOption
    {
        string RedirectUrl { get; }
        string ValidateUrl { get; }
        string SessionName { get; }
    }
}
