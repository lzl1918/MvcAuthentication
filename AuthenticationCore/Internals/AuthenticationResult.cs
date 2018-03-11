using AuthenticationCore.Internals.Helpers;
using System;
using System.Collections.Generic;
using System.Text;

namespace AuthenticationCore.Internals
{

    internal sealed class AuthenticationResult : IAuthenticationResult
    {
        private readonly bool isAuthenticated;
        private readonly bool isCAS;
        private readonly Type authenticator;
        private readonly IUser user;

        public bool IsAuthenticated => isAuthenticated;
        public bool IsCAS => isCAS;
        public Type Authenticator => authenticator;
        public IUser User => user;

        private AuthenticationResult(bool isAuthenticated, bool isCAS, Type authenticator, IUser user)
        {
            this.isAuthenticated = isAuthenticated;
            this.isCAS = isCAS;
            this.authenticator = authenticator;
            this.user = user;
        }

        internal static IAuthenticationResult Unauthenticated() => new AuthenticationResult(false, false, null, null);
        internal static IAuthenticationResult CAS(IUser user) => new AuthenticationResult(true, true, AuthenticationHelper.CAS_AUTHENTICATOR.Type, user);
        internal static IAuthenticationResult Authenticated(Type authenticator, IUser user)
        {
            if (authenticator.Equals(AuthenticationHelper.CAS_AUTHENTICATOR))
                return CAS(user);

            return new AuthenticationResult(true, false, authenticator, user);
        }
    }
}
