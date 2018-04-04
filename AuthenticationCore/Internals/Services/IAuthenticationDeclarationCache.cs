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
        private ICache<ControllerActionDescriptor, AuthenticationDeclarationInfo> mvcCache;
        private ICache<CompiledPageActionDescriptor, AuthenticationDeclarationInfo> pageCache;

        public AuthenticationDeclarationCache(int capacity)
        {
            mvcCache = new Cache<ControllerActionDescriptor, AuthenticationDeclarationInfo>(capacity, ComparerCollection.ControllerActionDescriptorComparer, ComparerCollection.ControllerActionDescriptorEqualityComparer);
            pageCache = new Cache<CompiledPageActionDescriptor, AuthenticationDeclarationInfo>(capacity, ComparerCollection.CompiledPageActionDescriptorComparer, ComparerCollection.CompiledPageActionDescriptorEqualityComparer);
        }

        public AuthenticationDeclarationInfo Get(ControllerActionDescriptor descriptor)
        {
            return mvcCache.Get(descriptor, CacheFallbackCollection.ControllerAuthenticationDeclarationFallback);
        }

        public AuthenticationDeclarationInfo Get(CompiledPageActionDescriptor descriptor)
        {
            return pageCache.Get(descriptor, CacheFallbackCollection.PageAuthenticationDeclarationFallback);
        }
    }
}
