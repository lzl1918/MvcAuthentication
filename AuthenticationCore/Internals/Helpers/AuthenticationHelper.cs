using AuthenticationCore.Authenticators;
using AuthenticationCore.Internals.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.RazorPages.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace AuthenticationCore.Internals.Helpers
{
    internal static class AuthenticationHelper
    {
        private static AuthenticatorMetadata casAuthenticatorData = null;
        private static object CASLocker = new object();
        internal static readonly Type CASAuthenticator = typeof(CASAuthenticator);

        private const string AUTHENTICATION_RESULT_KEY = "AUTHENTICATION_RESULT";
        internal static void SaveAuthenticationResult(HttpContext httpContext, IAuthenticationResult authenticationResult)
        {
            httpContext.Items[AUTHENTICATION_RESULT_KEY] = authenticationResult;
        }
        internal static IAuthenticationResult ReadAuthenticationResult(HttpContext httpContext)
        {
            if (httpContext.Items.TryGetValue(AUTHENTICATION_RESULT_KEY, out object value))
            {
                if (value is IAuthenticationResult result)
                    return result;
            }
            IAuthenticationResult tempresult = AuthenticationResult.Unauthenticated();
            SaveAuthenticationResult(httpContext, tempresult);
            return tempresult;
        }

        #region AUTHENTICATOR_EXECUTION
        internal static bool IsValidAuthenticator(IAuthenticatorMethodCache cache, Type authenticator, out AuthenticatorMetadata authenticateMethod)
        {
            authenticateMethod = cache.Get(authenticator);
            return authenticateMethod != null;
        }
        private static object[] PrepareMethodParameters(MethodInfo method, IServiceProvider services, HttpContext httpContext)
        {
            ParameterInfo[] parameters = method.GetParameters();
            if (parameters.Length <= 0)
                return null;

            object[] result = new object[parameters.Length];
            object value;
            int i = 0;
            foreach (ParameterInfo parameter in parameters)
            {
                if (parameter.ParameterType.Equals(typeof(HttpContext)))
                    result[i] = httpContext;
                else
                {
                    value = services.GetService(parameter.ParameterType);
                    if (value == null)
                    {
                        if (parameter.HasDefaultValue)
                            value = parameter.DefaultValue;
                        else
                            value = parameter.ParameterType.IsValueType ? Activator.CreateInstance(parameter.ParameterType) : null;
                    }
                    result[i] = value;
                }
                i++;
            }
            return result;
        }
        internal static AuthenticationInternalResult ExecuteAuthenticator(HttpContext httpContext, AuthenticatorMetadata authenticator)
        {
            IServiceProvider services = httpContext.RequestServices;
            MethodInfo authenticateMethod = authenticator.AuthenticateMethod;
            Type returnType = authenticateMethod.ReturnType;
            try
            {
                object auth = ActivatorUtilities.CreateInstance(services, authenticator.Type);
                object authenticate = authenticateMethod.Invoke(auth, PrepareMethodParameters(authenticateMethod, services, httpContext));
                switch (authenticator.ReturnType)
                {
                    case AuthenticateMethodReturnType.TaskWithIUser:
                        {
                            object awaiter = authenticator.GetAwaiter.Invoke(authenticate, null);
                            IUser result = (IUser)authenticator.GetResult.Invoke(awaiter, null);
                            if (result == null)
                                return null;
                            return new AuthenticationInternalResult(false, null, result, authenticator);
                        }

                    case AuthenticateMethodReturnType.IUser:
                    default:
                        {
                            IUser result = (IUser)authenticate;
                            if (result == null)
                                return null;
                            return new AuthenticationInternalResult(false, null, result, authenticator);
                        }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
                return null;
            }
        }
        internal static AuthenticationInternalResult ExecuteCAS(HttpContext httpContext)
        {
            lock (CASLocker)
            {
                if (casAuthenticatorData == null)
                {
                    IAuthenticatorMethodCache cache = httpContext.RequestServices.GetRequiredService<IAuthenticatorMethodCache>();
                    casAuthenticatorData = cache.Get(typeof(CASAuthenticator));
                }
                return ExecuteAuthenticator(httpContext, casAuthenticatorData);
            }
        }
        #endregion AUTHENTICATOR_EXECUTION

        #region AUTHENTICATION_EXECUTE

        // if casResult == null, the url does not contain ticket
        private static void CheckRequestUrl(HttpContext httpContext, out AuthenticationInternalResult casResult)
        {
            HttpRequest request = httpContext.Request;
            ICASOption option = httpContext.RequestServices.GetRequiredService<ICASOption>();
            IQueryCollection query = request.Query;
            string rawurl = request.GetDisplayUrl();
            if (query.TryGetValue("ticket", out StringValues ticketValue))
            {
                string ticket = ticketValue.ToArray()[0];
                string url = request.GetDisplayUrl();
                // remove ticket
                url = Regex.Replace(url, @"ticket\=[^\&]+\&?", "");
                while (url[url.Length - 1] == '&' || url[url.Length - 1] == '?')
                    url = url.Substring(0, url.Length - 1);
                string querystr = request.QueryString.Value;
                querystr = Regex.Replace(querystr, @"ticket\=[^\&]+\&?", "");
                while (querystr.Length > 0 && (querystr[querystr.Length - 1] == '&' || querystr[querystr.Length - 1] == '?'))
                    querystr = querystr.Substring(0, querystr.Length - 1);
                string url_not_escaped = url;
                url = url.EscapeAll();

                string target = $"{option.ValidateUrl}?service={url}&ticket={ticket}";
                request.QueryString = new QueryString(querystr);
                // validate
                // if true, set session
                try
                {
                    HttpClient client = new HttpClient();
                    HttpRequestMessage validateRequest = new HttpRequestMessage()
                    {
                        Method = HttpMethod.Get,
                        RequestUri = new Uri(target)
                    };
                    validateRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(option.ResponseAccept));
                    using (HttpResponseMessage response = client.SendAsync(validateRequest).GetAwaiter().GetResult())
                    {
                        if (response.StatusCode == System.Net.HttpStatusCode.OK)
                        {
                            string message = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                            Type handlerType = option.ResponseHandler;
                            ICASResponseHandler handler = (ICASResponseHandler)ActivatorUtilities.CreateInstance(httpContext.RequestServices, handlerType);
                            IUser user = handler.Invoke(httpContext, message, url_not_escaped, out string redirect_url);
                            if (redirect_url != null)
                            {
                                casResult = new AuthenticationInternalResult(false, redirect_url, null, null);
                                return;
                            }
                            if (user == null)
                            {
                                casResult = new AuthenticationInternalResult(true, null, null, null);
                                return;
                            }
                            else
                            {
                                lock (CASLocker)
                                {
                                    if (casAuthenticatorData == null)
                                    {
                                        IAuthenticatorMethodCache cache = httpContext.RequestServices.GetRequiredService<IAuthenticatorMethodCache>();
                                        casAuthenticatorData = cache.Get(typeof(CASAuthenticator));
                                    }
                                }
                                casResult = new AuthenticationInternalResult(false, null, user, casAuthenticatorData);
                                return;
                            }
                        }
                    }
                }
                catch
                {
                    casResult = null;
                }
            }
            casResult = null;
        }
        private static CustomAuthenticatorsAttribute[] GetCustomAuthenticators(TypeInfo type)
        {
            CustomAuthenticatorsAttribute[] result = type.GetAttributes<CustomAuthenticatorsAttribute>(false);
            if (result.Length > 0)
                return result;
            Type baseType = type.BaseType;
            if (baseType != null)
            {
                return GetCustomAuthenticators(baseType.GetTypeInfo());
            }
            return new CustomAuthenticatorsAttribute[] { };
        }
        private static AuthenticationInternalResult Authenticate(HttpContext httpContext, AuthenticationRequiredAttribute authAttribute, ICustomAttributeProvider attributeProvider)
        {
            CustomAuthenticatorsAttribute[] customAuthenticators = null;
            if (attributeProvider is TypeInfo controllerType)
            {
                customAuthenticators = GetCustomAuthenticators(controllerType);
            }
            else
            {
                customAuthenticators = attributeProvider.GetAttributes<CustomAuthenticatorsAttribute>(false);
            }
            AuthenticationInternalResult result = null;
            bool scanInherit = attributeProvider is TypeInfo;
            switch (authAttribute.Policy)
            {
                case AuthenticationPolicy.NoAuthentication:
                    return new AuthenticationInternalResult(true, null, null, null);

                case AuthenticationPolicy.All:
                    {
                        if (customAuthenticators.Length > 0)
                        {
                            Dictionary<CustomAuthenticatorExecutionPolicy, List<CustomAuthenticatorsAttribute>> authenticatorsGroups = GroupHelper.GroupBy(customAuthenticators, ag => ag.ExecutionPolicy);
                            result = TryAuthenticate(authenticatorsGroups, CustomAuthenticatorExecutionPolicy.BeforeCAS);
                            if (result != null)
                                return result;

                            result = ExecuteCAS(httpContext);
                            if (result != null)
                                return result;

                            result = TryAuthenticate(authenticatorsGroups, CustomAuthenticatorExecutionPolicy.AfterCAS);
                            if (result != null)
                                return result;
                        }
                        else
                        {
                            result = ExecuteCAS(httpContext);
                            if (result != null)
                                return result;
                        }
                    }
                    break;
                case AuthenticationPolicy.CASOnly:
                    {
                        result = ExecuteCAS(httpContext);
                        if (result != null)
                            return result;
                    }
                    break;
                case AuthenticationPolicy.DeclaredOnly:
                    {
                        if (customAuthenticators.Length > 0)
                        {
                            Dictionary<CustomAuthenticatorExecutionPolicy, List<CustomAuthenticatorsAttribute>> authenticatorsGroups = GroupHelper.GroupBy(customAuthenticators, ag => ag.ExecutionPolicy);
                            result = TryAuthenticate(authenticatorsGroups, CustomAuthenticatorExecutionPolicy.BeforeCAS);
                            if (result != null)
                                return result;

                            result = TryAuthenticate(authenticatorsGroups, CustomAuthenticatorExecutionPolicy.AfterCAS);
                            if (result != null)
                                return result;
                        }
                    }
                    break;
            }

            return null;

            AuthenticationInternalResult TryAuthenticate(Dictionary<CustomAuthenticatorExecutionPolicy, List<CustomAuthenticatorsAttribute>> groups, CustomAuthenticatorExecutionPolicy policy)
            {
                AuthenticationInternalResult tryResult;
                if (groups.TryGetValue(policy, out List<CustomAuthenticatorsAttribute> group))
                {
                    foreach (CustomAuthenticatorsAttribute auths in group)
                    {
                        tryResult = auths.Authenticate(httpContext);
                        if (tryResult != null)
                            return tryResult;
                    }
                    return null;
                }
                else
                    return null;
            }
        }
        private static AuthenticationInternalResult AuthenticateMvc(ControllerActionDescriptor actionDescriptor, HttpContext httpContext)
        {
            // first, check if the url contains ticket
            CheckRequestUrl(httpContext, out AuthenticationInternalResult result);
            if (result != null)
                return result;

            // then, check if the action needs authorization
            IAuthenticationDeclarationCache cache = httpContext.RequestServices.GetRequiredService<IAuthenticationDeclarationCache>();
            AuthenticationDeclarationInfo declarationInfo = cache.Get(actionDescriptor);
            AuthenticationDeclaration declaration = declarationInfo.Declaration;

            if (declaration == AuthenticationDeclaration.No)
            {
                return new AuthenticationInternalResult(true, null, null, null);
            }

            ICustomAttributeProvider attributeProvider = null;
            if (declaration == AuthenticationDeclaration.Action)
                attributeProvider = actionDescriptor.MethodInfo;
            else
                attributeProvider = actionDescriptor.ControllerTypeInfo;

            return Authenticate(httpContext, declarationInfo.Attribute, attributeProvider);
        }
        internal static AuthenticationInternalResult AuthenticateRazorPage(CompiledPageActionDescriptor actionDescriptor, HttpContext httpContext)
        {
            // first, check if the url contains ticket
            CheckRequestUrl(httpContext, out AuthenticationInternalResult result);
            if (result != null)
                return result;

            // then, check if the action needs authorization
            IAuthenticationDeclarationCache cache = httpContext.RequestServices.GetRequiredService<IAuthenticationDeclarationCache>();
            AuthenticationDeclarationInfo declarationInfo = cache.Get(actionDescriptor);
            AuthenticationDeclaration declaration = declarationInfo.Declaration;
            if (declaration == AuthenticationDeclaration.No)
            {
                return new AuthenticationInternalResult(true, null, null, null);
            }

            ICustomAttributeProvider attributeProvider = null;
            if (declaration == AuthenticationDeclaration.HandlerMethod)
                attributeProvider = actionDescriptor.HandlerMethods[0].MethodInfo;
            else
                attributeProvider = actionDescriptor.ModelTypeInfo;

            return Authenticate(httpContext, declarationInfo.Attribute, attributeProvider);
        }

        internal static AuthenticationInternalResult Authenticate(AuthorizationFilterContext context)
        {
            HttpContext httpContext = context.HttpContext;
            switch (context.ActionDescriptor)
            {
                case ControllerActionDescriptor controllerActionDescriptor:
                    return AuthenticateMvc(controllerActionDescriptor, httpContext);
                case CompiledPageActionDescriptor compiledPageActionDescriptor:
                    return AuthenticateRazorPage(compiledPageActionDescriptor, httpContext);
            }
            return new AuthenticationInternalResult(true, null, null, null);
        }

        #endregion AUTHENTICATION_EXECUTE

        #region CUSTOM_HANDLER_EXECUTE
        private static object[] PrepareHandlerMethodParameters(MethodInfo method, IServiceProvider services, HttpContext httpContext, AuthenticationPolicy policy, Type[] customAuthenticators)
        {
            ParameterInfo[] parameters = method.GetParameters();
            if (parameters.Length <= 0)
                return null;

            object[] result = new object[parameters.Length];
            object value;
            int i = 0;
            foreach (ParameterInfo parameter in parameters)
            {
                if (parameter.ParameterType.Equals(typeof(HttpContext)))
                    result[i] = httpContext;
                else if (parameter.ParameterType.Equals(typeof(AuthenticationPolicy)))
                    result[i] = policy;
                else if ((parameter.ParameterType.Equals(typeof(Type[])) || parameter.ParameterType.Equals(typeof(IEnumerable<Type>))))
                    result[i] = customAuthenticators;
                else if ((parameter.ParameterType.Equals(typeof(List<Type>)) || parameter.ParameterType.Equals(typeof(IList<Type>)) || parameter.ParameterType.Equals(typeof(IReadOnlyList<Type>))))
                    result[i] = customAuthenticators.ToList();
                else
                {
                    value = services.GetService(parameter.ParameterType);
                    if (value == null)
                    {
                        if (parameter.HasDefaultValue)
                            value = parameter.DefaultValue;
                        else
                            value = parameter.ParameterType.IsValueType ? Activator.CreateInstance(parameter.ParameterType) : null;
                    }
                    result[i] = value;
                }
                i++;
            }
            return result;
        }

        internal static IActionResult ExecuteHandler(Type handler, object[] constructParameters, HttpContext httpContext, AuthenticationPolicy policy, Type[] customAuthenticators)
        {
            IServiceProvider services = httpContext.RequestServices;
            IHandlerInvokeMethodCache cache = services.GetRequiredService<IHandlerInvokeMethodCache>();
            InvokeMethodInfo methodInfo = cache.Get(handler);
            if (methodInfo != null)
                return ExecuteMethod(methodInfo);

            return null;

            IActionResult ExecuteMethod(InvokeMethodInfo info)
            {
                try
                {
                    MethodInfo method = info.Method;
                    object handler_instance = ActivatorUtilities.CreateInstance(services, handler, constructParameters);
                    object invoke_result = method.Invoke(handler_instance, PrepareHandlerMethodParameters(method, services, httpContext, policy, customAuthenticators));
                    switch (info.ReturnType)
                    {
                        case InvokeMethodReturnType.Void:
                            return null;

                        case InvokeMethodReturnType.Task:
                            {
                                Task result = (Task)invoke_result;
                                if (result == null)
                                    return null;
                                if (result.Status == TaskStatus.WaitingToRun || result.Status == TaskStatus.Created)
                                    result.Start();
                                result.Wait();
                                return null;
                            }

                        case InvokeMethodReturnType.TaskWithIActionResult:
                            {
                                object awaiter = info.GetAwaiter.Invoke(invoke_result, null);
                                IActionResult result = (IActionResult)info.GetResult.Invoke(awaiter, null);
                                if (result == null)
                                    return null;
                                return result;
                            }

                        case InvokeMethodReturnType.IActionResult:
                        default:
                            {
                                IActionResult result = (IActionResult)invoke_result;
                                if (result == null)
                                    return null;
                                return result;
                            }

                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine(ex);
                    return null;
                }
            }
        }
        #endregion CUSTOM_HANDLER_EXECUTE
    }
}
