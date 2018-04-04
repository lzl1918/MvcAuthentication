using Hake.Extension.Cache;
using System;
using System.Reflection;

namespace AuthenticationCore.Internals.Services
{
    internal interface IAuthenticatorMethodCache
    {
        AuthenticatorMetadata Get(Type authentiatorType);
    }

    internal sealed class AuthenticatorMethodCache : IAuthenticatorMethodCache
    {
        private ICache<Type, AuthenticatorMetadata> cache;

        public AuthenticatorMethodCache(int capacity)
        {
            cache = new Cache<Type, AuthenticatorMetadata>(capacity, ComparerCollection.TypeComparer);
        }

        public AuthenticatorMetadata Get(Type authentiatorType)
        {
            return cache.Get(authentiatorType, CacheFallbackCollection.AuthenticateMethodFallback);
        }
    }

}
