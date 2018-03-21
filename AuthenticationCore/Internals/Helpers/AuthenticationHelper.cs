using AuthenticationCore.Authenticators;
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
        private static Type IUSER_TYPE { get; } = typeof(IUser);
        private static Type TASK_TYPE { get; } = typeof(Task<int>).GetGenericTypeDefinition();
        private static Type BASE_TASK_TYPE { get; } = typeof(Task);
        private static Type IACTIONRESULT_TYPE { get; } = typeof(IActionResult);
        private static Type VOID_TYPE { get; } = typeof(void);

        internal static AuthenticatorMetadata CAS_AUTHENTICATOR { get; } = new AuthenticatorMetadata(typeof(CASAuthenticator), typeof(CASAuthenticator).GetMethod("Authenticate"));

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
        internal static bool IsValidAuthenticator(Type authenticator, out MethodInfo authenticateMethod)
        {
            MethodInfo method = authenticator.GetMethod("AuthenticateAsync", BindingFlags.Public | BindingFlags.DeclaredOnly | BindingFlags.Instance);
            if (method != null
                && IsValidReturnType(method))
            {
                authenticateMethod = method;
                return true;
            }
            method = authenticator.GetMethod("Authenticate", BindingFlags.Public | BindingFlags.DeclaredOnly | BindingFlags.Instance);
            if (method != null
                && IsValidReturnType(method))
            {
                authenticateMethod = method;
                return true;
            }
            authenticateMethod = null;
            return false;

            bool IsValidReturnType(MethodInfo methodInfo)
            {
                Type returnType = methodInfo.ReturnType;
                if (returnType.IsGenericType && returnType.GetGenericTypeDefinition().Equals(TASK_TYPE))
                {
                    Type innerType = returnType.GetGenericArguments()[0];
                    if (IUSER_TYPE.IsAssignableFrom(innerType))
                    {
                        return true;
                    }
                }
                else if (IUSER_TYPE.IsAssignableFrom(returnType))
                {
                    return true;
                }
                return false;
            }
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
                if (returnType.IsGenericType && returnType.GetGenericTypeDefinition().Equals(TASK_TYPE))
                {
                    MethodInfo getAwaiterMethod = returnType.GetMethod("GetAwaiter", BindingFlags.Public | BindingFlags.Instance);
                    object awaiter = getAwaiterMethod.Invoke(authenticate, null);
                    Type awaiterType = awaiter.GetType();
                    MethodInfo getResultMethod = awaiterType.GetMethod("GetResult", BindingFlags.Public | BindingFlags.Instance);
                    IUser result = (IUser)getResultMethod.Invoke(awaiter, null);
                    if (result == null)
                        return null;
                    return new AuthenticationInternalResult(false, null, result, authenticator);
                }
                else
                {
                    IUser result = (IUser)authenticate;
                    if (result == null)
                        return null;
                    return new AuthenticationInternalResult(false, null, result, authenticator);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
                return null;
            }
        }
        internal static AuthenticationInternalResult ExecuteCAS(HttpContext httpContext) => ExecuteAuthenticator(httpContext, CAS_AUTHENTICATOR);
        #endregion AUTHENTICATOR_EXECUTION

        #region AUTHENTICATION_EXECUTE
        private enum AuthenticationDeclaration
        {
            No,
            Action,
            Controller
        }
        private static AuthenticationDeclaration IsAuthenticationRequired(ControllerActionDescriptor actionDescriptor, out AuthenticationRequiredAttribute authAttribute)
        {
            AuthenticationRequiredAttribute[] authRequired = actionDescriptor.MethodInfo.GetAttributes<AuthenticationRequiredAttribute>(false);
            if (authRequired.Length > 0)
            {
                authAttribute = authRequired[0];
                if (authAttribute.Policy == AuthenticationPolicy.NoAuthentication)
                    return AuthenticationDeclaration.No;
                return AuthenticationDeclaration.Action;
            }

            authRequired = actionDescriptor.ControllerTypeInfo.GetAttributes<AuthenticationRequiredAttribute>(true);
            if (authRequired.Length > 0)
            {
                authAttribute = authRequired[0];
                if (authAttribute.Policy == AuthenticationPolicy.NoAuthentication)
                    return AuthenticationDeclaration.No;
                return AuthenticationDeclaration.Controller;
            }

            authAttribute = null;
            return AuthenticationDeclaration.No;
        }
        private static AuthenticationDeclaration IsAuthenticationRequired(CompiledPageActionDescriptor actionDescriptor, out AuthenticationRequiredAttribute authAttribute)
        {
            HandlerMethodDescriptor handler = actionDescriptor.HandlerMethods.FirstOrDefault();
            AuthenticationRequiredAttribute[] authRequired;
            if (handler != null)
            {
                authRequired = handler.MethodInfo.GetAttributes<AuthenticationRequiredAttribute>(false);
                if (authRequired.Length > 0)
                {
                    authAttribute = authRequired[0];
                    if (authAttribute.Policy == AuthenticationPolicy.NoAuthentication)
                        return AuthenticationDeclaration.No;
                    return AuthenticationDeclaration.Action;
                }
            }
            authRequired = actionDescriptor.ModelTypeInfo.GetAttributes<AuthenticationRequiredAttribute>(true);
            if (authRequired.Length > 0)
            {
                authAttribute = authRequired[0];
                if (authAttribute.Policy == AuthenticationPolicy.NoAuthentication)
                    return AuthenticationDeclaration.No;
                return AuthenticationDeclaration.Controller;
            }
            authAttribute = null;
            return AuthenticationDeclaration.No;
        }

        // if casResult == null, the url does not contain ticket
        private static void CheckRequestUrl(HttpContext httpContext, out AuthenticationInternalResult casResult)
        {
            HttpRequest request = httpContext.Request;
            ICASOption option = (ICASOption)httpContext.RequestServices.GetService(typeof(ICASOption));
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
                    client.DefaultRequestHeaders.Accept.Clear();
                    client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue(option.ResponseAccept));
                    using (HttpResponseMessage response = client.GetAsync(target).GetAwaiter().GetResult())
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
                                casResult = new AuthenticationInternalResult(false, null, user, CAS_AUTHENTICATOR);
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
            AuthenticationDeclaration declaration = IsAuthenticationRequired(actionDescriptor, out AuthenticationRequiredAttribute authAttribute);

            if (declaration == AuthenticationDeclaration.No)
            {
                return new AuthenticationInternalResult(true, null, null, null);
            }

            ICustomAttributeProvider attributeProvider = null;
            if (declaration == AuthenticationDeclaration.Action)
                attributeProvider = actionDescriptor.MethodInfo;
            else
                attributeProvider = actionDescriptor.ControllerTypeInfo;

            ISession session = httpContext.Session;
            return Authenticate(httpContext, authAttribute, attributeProvider);
        }
        internal static AuthenticationInternalResult AuthenticateRazorPage(CompiledPageActionDescriptor actionDescriptor, HttpContext httpContext)
        {
            // first, check if the url contains ticket
            CheckRequestUrl(httpContext, out AuthenticationInternalResult result);
            if (result != null)
                return result;

            // then, check if the action needs authorization
            AuthenticationDeclaration declaration = IsAuthenticationRequired(actionDescriptor, out AuthenticationRequiredAttribute authAttribute);

            if (declaration == AuthenticationDeclaration.No)
            {
                return new AuthenticationInternalResult(true, null, null, null);
            }

            ICustomAttributeProvider attributeProvider = null;
            if (declaration == AuthenticationDeclaration.Action)
                attributeProvider = actionDescriptor.HandlerMethods.First().MethodInfo;
            else
                attributeProvider = actionDescriptor.ModelTypeInfo;

            ISession session = httpContext.Session;
            return Authenticate(httpContext, authAttribute, attributeProvider);
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

        internal static IActionResult ExecuteHandler(Type handler, HttpContext httpContext, AuthenticationPolicy policy, Type[] customAuthenticators)
        {
            IServiceProvider services = httpContext.RequestServices;
            MethodInfo method = handler.GetMethod("InvokeAsync", BindingFlags.Public | BindingFlags.DeclaredOnly | BindingFlags.Instance);
            if (method != null
                && IsValidReturnType(method))
            {
                return ExecuteMethod(method);
            }

            method = handler.GetMethod("Invoke", BindingFlags.Public | BindingFlags.DeclaredOnly | BindingFlags.Instance);
            if (method != null
                && IsValidReturnType(method))
            {
                return ExecuteMethod(method);
            }
            return null;

            bool IsValidReturnType(MethodInfo methodInfo)
            {
                Type returnType = methodInfo.ReturnType;
                if (returnType.IsGenericType && returnType.GetGenericTypeDefinition().Equals(TASK_TYPE))
                {
                    Type innerType = returnType.GetGenericArguments()[0];
                    if (IACTIONRESULT_TYPE.IsAssignableFrom(innerType))
                    {
                        return true;
                    }
                }
                else if (BASE_TASK_TYPE.IsAssignableFrom(returnType))
                {
                    return true;
                }
                else if (returnType.Equals(VOID_TYPE))
                {
                    return true;
                }
                else if (IACTIONRESULT_TYPE.IsAssignableFrom(returnType))
                {
                    return true;
                }
                return false;
            }
            IActionResult ExecuteMethod(MethodInfo methodInfo)
            {
                Type returnType = methodInfo.ReturnType;
                try
                {
                    object handler_instance = ActivatorUtilities.CreateInstance(services, handler);
                    object invoke_result = methodInfo.Invoke(handler_instance, PrepareHandlerMethodParameters(methodInfo, services, httpContext, policy, customAuthenticators));
                    if (returnType.IsGenericType && returnType.GetGenericTypeDefinition().Equals(TASK_TYPE))
                    {
                        MethodInfo getAwaiterMethod = returnType.GetMethod("GetAwaiter", BindingFlags.Public | BindingFlags.Instance);
                        object awaiter = getAwaiterMethod.Invoke(invoke_result, null);
                        Type awaiterType = awaiter.GetType();
                        MethodInfo getResultMethod = awaiterType.GetMethod("GetResult", BindingFlags.Public | BindingFlags.Instance);
                        IActionResult result = (IActionResult)getResultMethod.Invoke(awaiter, null);
                        if (result == null)
                            return null;
                        return result;
                    }
                    else if (BASE_TASK_TYPE.IsAssignableFrom(returnType))
                    {
                        Task result = (Task)invoke_result;
                        if (result == null)
                            return null;
                        if (result.Status == TaskStatus.WaitingToRun || result.Status == TaskStatus.Created)
                            result.Start();
                        result.Wait();
                        return null;
                    }
                    else if (returnType.Equals(VOID_TYPE))
                    {
                        return null;
                    }
                    else
                    {
                        IActionResult result = (IActionResult)invoke_result;
                        if (result == null)
                            return null;
                        return result;
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
