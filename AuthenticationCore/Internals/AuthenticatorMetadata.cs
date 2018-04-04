using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;

namespace AuthenticationCore.Internals
{
    internal enum AuthenticateMethodReturnType
    {
        IUser,
        TaskWithIUser
    }
    internal sealed class AuthenticatorMetadata
    {
        public Type Type { get; }
        public MethodInfo AuthenticateMethod { get; }
        public AuthenticateMethodReturnType ReturnType { get; }
        public MethodInfo GetAwaiter { get; }
        public MethodInfo GetResult { get; }

        internal AuthenticatorMetadata(Type type, MethodInfo authenticateMethod, AuthenticateMethodReturnType returnType, MethodInfo getAwaiter, MethodInfo getResult)
        {
            Type = type;
            AuthenticateMethod = authenticateMethod;
            ReturnType = returnType;
            GetAwaiter = getAwaiter;
            GetResult = getResult;
        }
    }
}
