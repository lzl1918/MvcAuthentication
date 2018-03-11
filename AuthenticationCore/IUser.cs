using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace AuthenticationCore
{
    public interface IUser
    {
        string Name { get; }
        ClaimsPrincipal Claims { get; }
    }
}
