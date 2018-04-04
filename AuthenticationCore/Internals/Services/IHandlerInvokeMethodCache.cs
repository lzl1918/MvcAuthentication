using Hake.Extension.Cache;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;

namespace AuthenticationCore.Internals.Services
{
    internal enum InvokeMethodReturnType
    {
        Void,
        Task,
        IActionResult,
        TaskWithIActionResult
    }

    internal sealed class InvokeMethodInfo
    {
        public MethodInfo Method { get; }
        public InvokeMethodReturnType ReturnType { get; }
        public MethodInfo GetAwaiter { get; }
        public MethodInfo GetResult { get; }

        public InvokeMethodInfo(MethodInfo method, InvokeMethodReturnType returnType, MethodInfo getAwaiter, MethodInfo getResult)
        {
            Method = method;
            ReturnType = returnType;
            GetAwaiter = getAwaiter;
            GetResult = getResult;
        }
    }

    internal interface IHandlerInvokeMethodCache
    {
        InvokeMethodInfo Get(Type handlerType);
    }

    internal sealed class HandlerInvokeMethodCache : IHandlerInvokeMethodCache
    {

        private ICache<Type, InvokeMethodInfo> cache;

        public HandlerInvokeMethodCache(int capacity)
        {
            cache = new Cache<Type, InvokeMethodInfo>(capacity, ComparerCollection.TypeComparer);
        }

        public InvokeMethodInfo Get(Type handlerType)
        {
            return cache.Get(handlerType, CacheFallbackCollection.HandlerInvokeMethodFallback);
        }
    }

}
