using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;

namespace AuthenticationCore.Internals
{
    internal sealed class AuthenticationInternalResult
    {
        public bool KeepUnauthenticated { get; }
        public bool IsRredirect => RedirectUrl != null;
        public string RedirectUrl { get; }
        public IUser User { get; }
        public AuthenticatorMetadata Authenticator { get; }

        internal AuthenticationInternalResult(bool keepUnauthenticated, string redirect_url, IUser user, AuthenticatorMetadata authenticator)
        {
            KeepUnauthenticated = keepUnauthenticated;
            RedirectUrl = redirect_url;
            User = user;
            Authenticator = authenticator;
        }
    }
}
