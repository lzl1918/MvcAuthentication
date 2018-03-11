using AuthenticationCore.Internals;
using AuthenticationCore.Internals.Helpers;
using AuthenticationCore.Internals.ResponseResults;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
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
            Debug.WriteLine("on authorization: " + context.ActionDescriptor.DisplayName, "AUTH");
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

                case AuthenticationFailedAction.Return401:
                    context.Result = new HttpAuthenticationForbiddenResult();
                    return;

                case AuthenticationFailedAction.CustomHandler:
                    {
                        ControllerActionDescriptor actionDescriptor = (ControllerActionDescriptor)context.ActionDescriptor;
                        List<Type> customAuthenticators = new List<Type>();
                        if (actionDescriptor.MethodInfo.HasAttribute<AuthenticationRequiredAttribute>(false))
                        {
                            foreach (CustomAuthenticatorsAttribute authenticators in actionDescriptor.MethodInfo.GetAttributes<CustomAuthenticatorsAttribute>(false))
                            {
                                customAuthenticators.AddRange(authenticators.Authenticators.Select(x => x.Type));
                            }
                        }
                        else
                        {
                            Type baseType;
                            TypeInfo controllerType;
                            while (true)
                            {
                                controllerType = actionDescriptor.ControllerTypeInfo;
                                if (actionDescriptor.MethodInfo.HasAttribute<AuthenticationRequiredAttribute>(false))
                                {
                                    foreach (CustomAuthenticatorsAttribute authenticators in actionDescriptor.MethodInfo.GetAttributes<CustomAuthenticatorsAttribute>(false))
                                    {
                                        customAuthenticators.AddRange(authenticators.Authenticators.Select(x => x.Type));
                                    }
                                    break;
                                }
                                baseType = controllerType.BaseType;
                                if (baseType == null)
                                    break;

                                controllerType = baseType.GetTypeInfo();
                            }
                        }

                        CustomHandlerAttribute[] handlers = actionDescriptor.MethodInfo.GetCustomAttributes(typeof(CustomHandlerAttribute), false).Cast<CustomHandlerAttribute>().ToArray();
                        if (handlers.Length > 0)
                        {
                            IActionResult actionResult = AuthenticationHelper.ExecuteHandler(handlers[0].Handler, httpContext, Policy, customAuthenticators.ToArray());
                            if (actionResult != null)
                            {
                                context.Result = actionResult;
                                return;
                            }
                            else
                            {
                                // not handled
                            }
                        }
                    }
                    return;
            }
        }
    }
}