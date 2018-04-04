using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;
using System.Collections.Generic;

namespace AuthenticationCore.Internals.Services
{
    internal static class ComparerCollection
    {
        private sealed class InternalTypeComparer : IComparer<Type>
        {
            public int Compare(Type x, Type y)
            {
                return x.FullName.CompareTo(y.FullName);
            }
        }

        internal static readonly IComparer<Type> TypeComparer = new InternalTypeComparer();


        private sealed class InternalControllerActionDescriptorComparer : IComparer<ControllerActionDescriptor>, IEqualityComparer<ControllerActionDescriptor>
        {
            public int Compare(ControllerActionDescriptor x, ControllerActionDescriptor y)
            {
                string xName = $"{x.ControllerTypeInfo.FullName}.{x.MethodInfo.Name}";
                string yName = $"{y.ControllerTypeInfo.FullName}.{y.MethodInfo.Name}";
                return xName.CompareTo(yName);
            }

            public bool Equals(ControllerActionDescriptor x, ControllerActionDescriptor y)
            {
                return
                    x.ControllerTypeInfo.Equals(y.ControllerTypeInfo) &&
                    x.MethodInfo.Equals(y.MethodInfo);
            }

            public int GetHashCode(ControllerActionDescriptor obj)
            {
                return obj.ControllerTypeInfo.GetHashCode() ^ obj.MethodInfo.GetHashCode();
            }
        }
        internal static readonly IComparer<ControllerActionDescriptor> ControllerActionDescriptorComparer = new InternalControllerActionDescriptorComparer();
        internal static readonly IEqualityComparer<ControllerActionDescriptor> ControllerActionDescriptorEqualityComparer = new InternalControllerActionDescriptorComparer();

        private sealed class InternalCompiledPageActionDescriptorComparer : IComparer<CompiledPageActionDescriptor>, IEqualityComparer<CompiledPageActionDescriptor>
        {
            public int Compare(CompiledPageActionDescriptor x, CompiledPageActionDescriptor y)
            {
                string xName = $"{x.ModelTypeInfo.FullName}.{x.HandlerMethods[0].Name}";
                string yName = $"{y.ModelTypeInfo.FullName}.{y.HandlerMethods[0].Name}";
                return xName.CompareTo(yName);
            }

            public bool Equals(CompiledPageActionDescriptor x, CompiledPageActionDescriptor y)
            {
                return
                    x.ModelTypeInfo.Equals(y.ModelTypeInfo) &&
                    x.HandlerMethods[0].Equals(y.HandlerMethods[0]);
            }

            public int GetHashCode(CompiledPageActionDescriptor obj)
            {
                return obj.ModelTypeInfo.GetHashCode() ^ obj.HandlerMethods[0].GetHashCode();
            }
        }
        internal static readonly IComparer<CompiledPageActionDescriptor> CompiledPageActionDescriptorComparer = new InternalCompiledPageActionDescriptorComparer();
        internal static readonly IEqualityComparer<CompiledPageActionDescriptor> CompiledPageActionDescriptorEqualityComparer = new InternalCompiledPageActionDescriptorComparer();
    }

}
