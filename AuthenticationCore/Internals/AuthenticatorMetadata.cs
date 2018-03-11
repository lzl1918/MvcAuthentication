using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;

namespace AuthenticationCore.Internals
{
    internal sealed class AuthenticatorMetadata
    {
        public Type Type { get; }
        public MethodInfo AuthenticateMethod { get; }
        
        internal AuthenticatorMetadata(Type type, MethodInfo authenticateMethod)
        {
            Type = type;
            AuthenticateMethod = authenticateMethod;
        }
    }
}
