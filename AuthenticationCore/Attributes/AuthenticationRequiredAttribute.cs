using AuthenticationCore.Internals;
using AuthenticationCore.Internals.Helpers;
using AuthenticationCore.Internals.ResponseResults;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.RazorPages.Infrastructure;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Text;

namespace AuthenticationCore
{

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false)]
    public class AuthenticationRequiredAttribute : Attribute, IAuthorizationFilter
    {
        public AuthenticationRequiredAttribute(AuthenticationPolicy policy = AuthenticationPolicy.All, AuthenticationFailedAction failedAction = AuthenticationFailedAction.KeepUnauthenticated)
        {
            Policy = policy;
            FailedAction = failedAction;
        }

        public AuthenticationPolicy Policy { get; }
        public AuthenticationFailedAction FailedAction { get; }

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            HttpContext httpContext = context.HttpContext;
            AuthenticationInternalResult authresult = AuthenticationHelper.Authenticate(context);
            if (authresult != null)
            {
                if (authresult.IsRredirect)
                {
                    context.Result = new RedirectResult(authresult.RedirectUrl, true);
                    return;
                }
                else if (authresult.KeepUnauthenticated)
                {
                    IAuthenticationResult unauthenticatedResult = AuthenticationResult.Unauthenticated();
                    AuthenticationHelper.SaveAuthenticationResult(httpContext, unauthenticatedResult);
                    return;
                }
                else
                {
                    IAuthenticationResult authenticationResult = AuthenticationResult.Authenticated(authresult.Authenticator.Type, authresult.User);
                    AuthenticationHelper.SaveAuthenticationResult(httpContext, authenticationResult);
                    return;
                }

            }

            switch (FailedAction)
            {
                case AuthenticationFailedAction.KeepUnauthenticated:
                    {
                        IAuthenticationResult unauthenticatedResult = AuthenticationResult.Unauthenticated();
                        AuthenticationHelper.SaveAuthenticationResult(httpContext, unauthenticatedResult);
                        return;
                    }

                case AuthenticationFailedAction.RedirectCAS:
                    context.Result = new HttpCASRedirectResult();
                    return;

                case AuthenticationFailedAction.Return403:
                    context.Result = new HttpAuthenticationForbiddenResult();
                    return;

                case AuthenticationFailedAction.CustomHandler:
                    {
                        List<Type> customAuthenticators = null;
                        AuthenticationFailedHandlerAttribute[] handlers = null;
                        switch (context.ActionDescriptor)
                        {
                            case ControllerActionDescriptor controllerActionDescriptor:
                                customAuthenticators = GetCustomAuthenticators(controllerActionDescriptor);
                                handlers = GetCustomHandlers(controllerActionDescriptor);
                                break;
                            case CompiledPageActionDescriptor compiledPageActionDescriptor:
                                customAuthenticators = GetCustomAuthenticators(compiledPageActionDescriptor);
                                handlers = GetCustomHandlers(compiledPageActionDescriptor);
                                break;
                            default:
                                throw new Exception($"not handled with action descriptor of type {context.ActionDescriptor.GetType().Name}");
                        }

                        if (handlers != null && handlers.Length > 0)
                        {
                            IActionResult actionResult = AuthenticationHelper.ExecuteHandler(handlers[0].Handler, handlers[0].ConstructParameters, httpContext, Policy, customAuthenticators.ToArray());
                            if (actionResult != null)
                            {
                                context.Result = actionResult;
                                return;
                            }
                            else
                            {
                                // not handled
                                throw new Exception($"not handled");
                            }
                        }
                    }
                    return;
            }
        }
        private List<Type> GetCustomAuthenticators(ControllerActionDescriptor controllerActionDescriptor)
        {
            List<Type> result = new List<Type>();
            MethodInfo method = controllerActionDescriptor.MethodInfo;
            if (method.HasAttribute<AuthenticationRequiredAttribute>(false))
            {
                foreach (CustomAuthenticatorsAttribute authenticators in method.GetAttributes<CustomAuthenticatorsAttribute>(false))
                {
                    result.AddRange(authenticators.Authenticators);
                }
            }
            else
            {
                Type baseType;
                TypeInfo controllerType;
                while (true)
                {
                    controllerType = controllerActionDescriptor.ControllerTypeInfo;
                    if (controllerType.HasAttribute<AuthenticationRequiredAttribute>(false))
                    {
                        foreach (CustomAuthenticatorsAttribute authenticators in controllerType.GetAttributes<CustomAuthenticatorsAttribute>(false))
                        {
                            result.AddRange(authenticators.Authenticators);
                        }
                        break;
                    }
                    baseType = controllerType.BaseType;
                    if (baseType == null)
                        break;

                    controllerType = baseType.GetTypeInfo();
                }
            }
            return result;
        }
        private List<Type> GetCustomAuthenticators(CompiledPageActionDescriptor compiledPageActionDescriptor)
        {
            List<Type> result = new List<Type>();
            HandlerMethodDescriptor methodDescriptor = compiledPageActionDescriptor.HandlerMethods[0];
            bool checkPageModel = true;
            if (methodDescriptor != null)
            {
                MethodInfo method = methodDescriptor.MethodInfo;
                if (method.HasAttribute<AuthenticationRequiredAttribute>(false))
                {
                    foreach (CustomAuthenticatorsAttribute authenticators in method.GetAttributes<CustomAuthenticatorsAttribute>(false))
                    {
                        result.AddRange(authenticators.Authenticators);
                    }
                    checkPageModel = false;
                }
            }

            if (checkPageModel)
            {
                Type baseType;
                TypeInfo controllerType;
                while (true)
                {
                    controllerType = compiledPageActionDescriptor.ModelTypeInfo;
                    if (controllerType.HasAttribute<AuthenticationRequiredAttribute>(false))
                    {
                        foreach (CustomAuthenticatorsAttribute authenticators in controllerType.GetAttributes<CustomAuthenticatorsAttribute>(false))
                        {
                            result.AddRange(authenticators.Authenticators);
                        }
                        break;
                    }
                    baseType = controllerType.BaseType;
                    if (baseType == null)
                        break;

                    controllerType = baseType.GetTypeInfo();
                }
            }
            return result;
        }
        private AuthenticationFailedHandlerAttribute[] GetCustomHandlers(ControllerActionDescriptor controllerActionDescriptor)
        {
            List<AuthenticationFailedHandlerAttribute> result = new List<AuthenticationFailedHandlerAttribute>();
            MethodInfo method = controllerActionDescriptor.MethodInfo;
            if (method.HasAttribute<AuthenticationFailedHandlerAttribute>(false))
            {
                result.AddRange(method.GetCustomAttributes<AuthenticationFailedHandlerAttribute>(false));
            }
            else
            {
                Type baseType;
                TypeInfo controllerType;
                while (true)
                {
                    controllerType = controllerActionDescriptor.ControllerTypeInfo;
                    if (controllerType.HasAttribute<AuthenticationFailedHandlerAttribute>(false))
                    {
                        result.AddRange(controllerType.GetCustomAttributes<AuthenticationFailedHandlerAttribute>(false));
                        break;
                    }
                    baseType = controllerType.BaseType;
                    if (baseType == null)
                        break;

                    controllerType = baseType.GetTypeInfo();
                }
            }
            return result.ToArray();
        }
        private AuthenticationFailedHandlerAttribute[] GetCustomHandlers(CompiledPageActionDescriptor compiledPageActionDescriptor)
        {
            List<AuthenticationFailedHandlerAttribute> result = new List<AuthenticationFailedHandlerAttribute>();
            HandlerMethodDescriptor methodDescriptor = compiledPageActionDescriptor.HandlerMethods[0];
            bool checkPageModel = true;
            if (methodDescriptor != null)
            {
                MethodInfo method = methodDescriptor.MethodInfo;
                if (method.HasAttribute<AuthenticationFailedHandlerAttribute>(false))
                {
                    result.AddRange(method.GetCustomAttributes<AuthenticationFailedHandlerAttribute>(false));
                    checkPageModel = false;
                }
            }

            if (checkPageModel)
            {
                Type baseType;
                TypeInfo controllerType;
                while (true)
                {
                    controllerType = compiledPageActionDescriptor.ModelTypeInfo;
                    if (controllerType.HasAttribute<AuthenticationFailedHandlerAttribute>(false))
                    {
                        result.AddRange(controllerType.GetCustomAttributes<AuthenticationFailedHandlerAttribute>(false));
                        break;
                    }
                    baseType = controllerType.BaseType;
                    if (baseType == null)
                        break;

                    controllerType = baseType.GetTypeInfo();
                }
            }
            return result.ToArray();
        }
    }
}