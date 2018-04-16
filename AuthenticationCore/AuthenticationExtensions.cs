using AuthenticationCore.Internals;
using AuthenticationCore.Internals.Services;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Text;

namespace AuthenticationCore
{
    public static class AuthenticationExtensions
    {
        public static IServiceCollection AddMvcAuthentication(
            this IServiceCollection services,
            string redirectUrl,
            string validateUrl,
            string logoutUrl,
            string sessionName,
            Type responseHandler,
            string responseAccept = "application/json",
            int cacheCapacity = 100)
        {
            if (responseHandler.GetInterface(typeof(ICASResponseHandler).FullName) == null)
                throw new InvalidOperationException($"type {responseHandler.Name} does not implement interface {typeof(ICASResponseHandler).Name}");

            services.AddScoped<IAuthenticationResultAccessor, AuthenticationResultAccessor>();
            services.AddScoped<IAuthenticationResult, LateBoundAuthenticationResult>();
            services.AddScoped<IAuthenticationService, AuthenticationService>();
            services.AddSingleton<ICASOption>(new CASOption(redirectUrl, validateUrl, logoutUrl, sessionName, responseAccept, responseHandler));


            services.AddSingleton<IHandlerInvokeMethodCache>(new HandlerInvokeMethodCache(capacity: cacheCapacity));
            services.AddSingleton<IAuthenticationDeclarationCache>(new AuthenticationDeclarationCache(capacity: cacheCapacity));
            services.AddSingleton<IAuthenticatorMethodCache>(new AuthenticatorMethodCache(capacity: cacheCapacity));

            return services;
        }

        public static IServiceCollection AddMvcAuthentication<T>(this IServiceCollection services, string redirectUrl, string validateUrl, string logoutUrl, string sessionName, string responseAccept = "application/json") where T : ICASResponseHandler
        {
            return AddMvcAuthentication(services, redirectUrl, validateUrl, logoutUrl, sessionName, typeof(T), responseAccept);
        }

        public static IServiceCollection AddMvcAuthentication(this IServiceCollection services, string redirectUrl, string validateUrl, string logoutUrl, string sessionName, string responseAccept = "application/json")
        {
            return AddMvcAuthentication(services, redirectUrl, validateUrl, logoutUrl, sessionName, typeof(DefaultCASResponseHandler), responseAccept);
        }
    }
}
