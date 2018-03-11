using System;

namespace AuthenticationCore
{
    public interface IAuthenticationResult
    {
        bool IsAuthenticated { get; }
        bool IsCAS { get; }

        Type Authenticator { get; }
        IUser User { get; }
    }
}
