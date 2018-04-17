using Hake.Extension.Cache;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;
using System.Collections.Generic;
using System.Text;

namespace AuthenticationCore.Internals.Services
{
    internal enum AuthenticationDeclaration
    {
        No = 0,
        Action = 1,
        HandlerMethod = 1,

        Controller = 2,
        PageModel = 2
    }

    internal sealed class AuthenticationDeclarationInfo
    {
        public AuthenticationDeclaration Declaration { get; }
        public AuthenticationRequiredAttribute Attribute { get; }

        public AuthenticationDeclarationInfo(AuthenticationDeclaration declaration, AuthenticationRequiredAttribute attribute)
        {
            Declaration = declaration;
            Attribute = attribute;
        }
    }


    internal interface IAuthenticationDeclarationCache
    {
        AuthenticationDeclarationInfo Get(ControllerActionDescriptor descriptor);
        AuthenticationDeclarationInfo Get(CompiledPageActionDescriptor descriptor);
    }
    internal sealed class AuthenticationDeclarationCache : IAuthenticationDeclarationCache
    {
        private ICache<string, AuthenticationDeclarationInfo> mvcCache;
        private ICache<string, AuthenticationDeclarationInfo> pageCache;
        private object mvcLocker = new object();
        private object pageLocker = new object();

        public AuthenticationDeclarationCache(int capacity)
        {
            mvcCache = new Cache<string, AuthenticationDeclarationInfo>(capacity);
            pageCache = new Cache<string, AuthenticationDeclarationInfo>(capacity);
        }

        public AuthenticationDeclarationInfo Get(ControllerActionDescriptor descriptor)
        {
            lock (mvcLocker)
            {
                string key = $"{descriptor.ControllerTypeInfo.FullName}.{descriptor.MethodInfo.Name}";
                return mvcCache.Get(key, k => CacheFallbackCollection.ControllerAuthenticationDeclarationFallback(descriptor));
            }
        }

        public AuthenticationDeclarationInfo Get(CompiledPageActionDescriptor descriptor)
        {
            lock (pageLocker)
            {
                string key = $"{descriptor.ModelTypeInfo.FullName}.{descriptor.HandlerMethods[0].MethodInfo.Name}";
                return pageCache.Get(key, k => CacheFallbackCollection.PageAuthenticationDeclarationFallback(descriptor));
            }
        }
    }
}
