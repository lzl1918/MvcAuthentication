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
        internal static IAuthenticationResult CAS(IUser user) => new AuthenticationResult(true, true, AuthenticationHelper.CASAuthenticator, user);
        internal static IAuthenticationResult Authenticated(Type authenticator, IUser user)
        {
            if (authenticator.Equals(AuthenticationHelper.CASAuthenticator))
                return CAS(user);

            return new AuthenticationResult(true, false, authenticator, user);
        }
    }

    internal sealed class LateBoundAuthenticationResult : IAuthenticationResult
    {
        private readonly IAuthenticationResultAccessor accessor;
        private IAuthenticationResult actualResult;
        public bool IsAuthenticated => actualResult == null ? (actualResult = accessor.Result).IsAuthenticated : actualResult.IsAuthenticated;
        public bool IsCAS => actualResult == null ? (actualResult = accessor.Result).IsCAS : actualResult.IsCAS;
        public Type Authenticator => actualResult == null ? (actualResult = accessor.Result).Authenticator : actualResult.Authenticator;
        public IUser User => actualResult == null ? (actualResult = accessor.Result).User : actualResult.User;

        public LateBoundAuthenticationResult(IAuthenticationResultAccessor accessor)
        {
            this.accessor = accessor;
            accessor.ResultUpdated += OnResultUpdated;
        }
        ~LateBoundAuthenticationResult()
        {
            accessor.ResultUpdated -= OnResultUpdated;
        }
        private void OnResultUpdated(object sender, EventArgs e)
        {
            actualResult = accessor.Result;
        }
    }
}
