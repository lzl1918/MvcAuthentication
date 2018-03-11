using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace AuthenticationCore
{

    public interface IAuthenticationService
    {
        Task<IAuthenticationResult> CASAsync(bool saveResult = false);
        Task<IAuthenticationResult> AuthenticateAsync(
            IEnumerable<Type> authenticators,
            bool saveResult = false);

        IActionResult CreateRedirectCASResult();
    }
}
