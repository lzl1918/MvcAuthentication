using AuthenticationCore.Internals.Helpers;
using Hake.Extension.Cache;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.RazorPages.Infrastructure;
using System;
using System.Collections;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace AuthenticationCore.Internals.Services
{
    internal static class CacheFallbackCollection
    {
        private static readonly Type TaskType = typeof(Task<int>).GetGenericTypeDefinition();
        private static readonly Type BaseTaskType = typeof(Task);
        private static readonly Type IActionResultType = typeof(IActionResult);
        private static readonly Type VoidType = typeof(void);
        private static readonly Type IUserType = typeof(IUser);

        internal static readonly CacheFallBack<Type, InvokeMethodInfo> HandlerInvokeMethodFallback = key =>
        {
            MethodInfo method = key.GetMethod("InvokeAsync", BindingFlags.Public | BindingFlags.DeclaredOnly | BindingFlags.Instance);
            if (method != null &&
                TryValidateInvokeReturnType(method, out InvokeMethodInfo methodInfo))
            {
                return RetrivationResult<InvokeMethodInfo>.Create(methodInfo);
            }
            method = key.GetMethod("Invoke", BindingFlags.Public | BindingFlags.DeclaredOnly | BindingFlags.Instance);
            if (method != null &&
                TryValidateInvokeReturnType(method, out methodInfo))
            {
                return RetrivationResult<InvokeMethodInfo>.Create(methodInfo);
            }
            return RetrivationResult<InvokeMethodInfo>.Create(null);
        };
        private static bool TryValidateInvokeReturnType(MethodInfo method, out InvokeMethodInfo methodInfo)
        {
            Type returnType = method.ReturnType;
            if (returnType.IsGenericType && returnType.GetGenericTypeDefinition().Equals(TaskType))
            {
                Type innerType = returnType.GetGenericArguments()[0];
                if (IActionResultType.IsAssignableFrom(innerType))
                {
                    MethodInfo getAwaiterMethod = returnType.GetMethod("GetAwaiter", BindingFlags.Public | BindingFlags.Instance);
                    Type awaiterType = getAwaiterMethod.ReturnType;
                    MethodInfo getResultMethod = awaiterType.GetMethod("GetResult", BindingFlags.Public | BindingFlags.Instance);
                    methodInfo = new InvokeMethodInfo(method, InvokeMethodReturnType.TaskWithIActionResult, getAwaiterMethod, getResultMethod);
                    return true;
                }
            }
            else if (BaseTaskType.IsAssignableFrom(returnType))
            {
                methodInfo = new InvokeMethodInfo(method, InvokeMethodReturnType.Task, null, null);
                return true;
            }
            else if (returnType.Equals(VoidType))
            {
                methodInfo = new InvokeMethodInfo(method, InvokeMethodReturnType.Void, null, null);
                return true;
            }
            else if (IActionResultType.IsAssignableFrom(returnType))
            {
                methodInfo = new InvokeMethodInfo(method, InvokeMethodReturnType.IActionResult, null, null);
                return true;
            }
            methodInfo = null;
            return false;
        }

        internal static readonly CacheFallBack<Type, AuthenticatorMetadata> AuthenticateMethodFallback = key =>
        {
            MethodInfo method = key.GetMethod("AuthenticateAsync", BindingFlags.Public | BindingFlags.DeclaredOnly | BindingFlags.Instance);
            if (method != null &&
                TryValidateAuthenticateReturnType(key, method, out AuthenticatorMetadata methodInfo))
            {
                return RetrivationResult<AuthenticatorMetadata>.Create(methodInfo);
            }
            method = key.GetMethod("Authenticate", BindingFlags.Public | BindingFlags.DeclaredOnly | BindingFlags.Instance);
            if (method != null &&
                TryValidateAuthenticateReturnType(key, method, out methodInfo))
            {
                return RetrivationResult<AuthenticatorMetadata>.Create(methodInfo);
            }
            return RetrivationResult<AuthenticatorMetadata>.Create(null);
        };
        private static bool TryValidateAuthenticateReturnType(Type authenticator, MethodInfo method, out AuthenticatorMetadata methodInfo)
        {
            Type returnType = method.ReturnType;
            if (returnType.IsGenericType && returnType.GetGenericTypeDefinition().Equals(TaskType))
            {
                Type innerType = returnType.GetGenericArguments()[0];
                if (IUserType.IsAssignableFrom(innerType))
                {
                    MethodInfo getAwaiterMethod = returnType.GetMethod("GetAwaiter", BindingFlags.Public | BindingFlags.Instance);
                    Type awaiterType = getAwaiterMethod.ReturnType;
                    MethodInfo getResultMethod = awaiterType.GetMethod("GetResult", BindingFlags.Public | BindingFlags.Instance);
                    methodInfo = new AuthenticatorMetadata(authenticator, method, AuthenticateMethodReturnType.TaskWithIUser, getAwaiterMethod, getResultMethod);
                    return true;
                }
            }
            else if (IUserType.IsAssignableFrom(returnType))
            {
                methodInfo = new AuthenticatorMetadata(authenticator, method, AuthenticateMethodReturnType.IUser, null, null);
                return true;
            }
            methodInfo = null;
            return false;
        }


        internal static readonly CacheFallBack<ControllerActionDescriptor, AuthenticationDeclarationInfo> ControllerAuthenticationDeclarationFallback = key =>
        {
            AuthenticationRequiredAttribute[] authRequired = key.MethodInfo.GetAttributes<AuthenticationRequiredAttribute>(false);
            AuthenticationRequiredAttribute authAttribute = null;
            if (authRequired.Length > 0)
            {
                authAttribute = authRequired[0];
                if (authAttribute.Policy == AuthenticationPolicy.NoAuthentication)
                    return RetrivationResult<AuthenticationDeclarationInfo>.Create(new AuthenticationDeclarationInfo(AuthenticationDeclaration.No, authAttribute));
                return RetrivationResult<AuthenticationDeclarationInfo>.Create(new AuthenticationDeclarationInfo(AuthenticationDeclaration.Action, authAttribute));
            }

            authRequired = key.ControllerTypeInfo.GetAttributes<AuthenticationRequiredAttribute>(true);
            if (authRequired.Length > 0)
            {
                authAttribute = authRequired[0];
                if (authAttribute.Policy == AuthenticationPolicy.NoAuthentication)
                    return RetrivationResult<AuthenticationDeclarationInfo>.Create(new AuthenticationDeclarationInfo(AuthenticationDeclaration.No, authAttribute));
                return RetrivationResult<AuthenticationDeclarationInfo>.Create(new AuthenticationDeclarationInfo(AuthenticationDeclaration.Controller, authAttribute));
            }
            return RetrivationResult<AuthenticationDeclarationInfo>.Create(new AuthenticationDeclarationInfo(AuthenticationDeclaration.No, null));
        };
        internal static readonly CacheFallBack<CompiledPageActionDescriptor, AuthenticationDeclarationInfo> PageAuthenticationDeclarationFallback = key =>
        {
            HandlerMethodDescriptor handler = key.HandlerMethods[0];
            AuthenticationRequiredAttribute[] authRequired;
            AuthenticationRequiredAttribute authAttribute = null;
            if (handler != null)
            {
                authRequired = handler.MethodInfo.GetAttributes<AuthenticationRequiredAttribute>(false);
                if (authRequired.Length > 0)
                {
                    authAttribute = authRequired[0];
                    if (authAttribute.Policy == AuthenticationPolicy.NoAuthentication)
                        return RetrivationResult<AuthenticationDeclarationInfo>.Create(new AuthenticationDeclarationInfo(AuthenticationDeclaration.No, authAttribute));
                    return RetrivationResult<AuthenticationDeclarationInfo>.Create(new AuthenticationDeclarationInfo(AuthenticationDeclaration.HandlerMethod, authAttribute));
                }
            }
            authRequired = key.ModelTypeInfo.GetAttributes<AuthenticationRequiredAttribute>(true);
            if (authRequired.Length > 0)
            {
                authAttribute = authRequired[0];
                if (authAttribute.Policy == AuthenticationPolicy.NoAuthentication)
                    return RetrivationResult<AuthenticationDeclarationInfo>.Create(new AuthenticationDeclarationInfo(AuthenticationDeclaration.No, authAttribute));
                return RetrivationResult<AuthenticationDeclarationInfo>.Create(new AuthenticationDeclarationInfo(AuthenticationDeclaration.PageModel, authAttribute));
            }
            return RetrivationResult<AuthenticationDeclarationInfo>.Create(new AuthenticationDeclarationInfo(AuthenticationDeclaration.No, null));
        };
    }

}
