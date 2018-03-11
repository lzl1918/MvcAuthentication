using AuthenticationCore.Internals;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;

namespace AuthenticationCore.Authenticators
{
    public class CASAuthenticator
    {
        public virtual IUser Authenticate(HttpContext httpContext, ICASOption option)
        {
            ISession session = httpContext.Session;
            if (session == null)
                return null;

            string displayName = session.GetString(option.SessionName);
            if (displayName == null)
                return null;

            ClaimsPrincipal userClaims = new ClaimsPrincipal();
            ClaimsIdentity identity = new ClaimsIdentity(nameof(CASAuthenticator));
            identity.AddClaim(new Claim("Name", displayName));
            userClaims.AddIdentity(identity);
            httpContext.User = userClaims;
            IUser user = new User(displayName, userClaims);
            return user;
        }
    }
}
