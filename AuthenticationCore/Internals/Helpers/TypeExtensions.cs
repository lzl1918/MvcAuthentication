using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;

namespace AuthenticationCore.Internals.Helpers
{
    internal static class TypeExtensions
    {
        internal static T[] GetAttributes<T>(this ICustomAttributeProvider attributeProvider, bool inherit)
        {
            return attributeProvider.GetCustomAttributes(typeof(T), inherit).Cast<T>().ToArray();
        }
        internal static bool HasAttribute<T>(this ICustomAttributeProvider attributeProvider, bool inherit)
        {
            return attributeProvider.GetCustomAttributes(typeof(T), inherit).Length > 0;
        }
    }
}
