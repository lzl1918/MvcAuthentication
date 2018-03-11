using AuthenticationCore.Internals;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
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

            IUser user = new User(displayName);
            return user;
        }
    }
}
