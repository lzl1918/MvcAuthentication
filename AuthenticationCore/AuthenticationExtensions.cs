using AuthenticationCore.Internals;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Text;

namespace AuthenticationCore
{
    public static class AuthenticationExtensions
    {
        public static IServiceCollection AddMvcAuthentication(this IServiceCollection services, string redirectUrl, string validateUrl, string sessionName, Type responseHandler, string responseAccept = "application/json")
        {
            if (responseHandler.GetInterface(typeof(ICASResponseHandler).FullName) == null)
                throw new InvalidOperationException($"type {responseHandler.Name} does not implement interface {typeof(ICASResponseHandler).Name}");

            services.AddScoped<IAuthenticationResultAccessor, AuthenticationResultAccessor>();
            services.AddScoped<IAuthenticationResult, LateBoundAuthenticationResult>();
            services.AddScoped<IAuthenticationService, AuthenticationService>();
            services.AddSingleton<ICASOption>(new CASOption(redirectUrl, validateUrl, sessionName, responseAccept, responseHandler));
            return services;
        }

        public static IServiceCollection AddMvcAuthentication<T>(this IServiceCollection services, string redirectUrl, string validateUrl, string sessionName, string responseAccept = "application/json") where T : ICASResponseHandler
        {
            return AddMvcAuthentication(services, redirectUrl, validateUrl, sessionName, typeof(T), responseAccept);
        }

        public static IServiceCollection AddMvcAuthentication(this IServiceCollection services, string redirectUrl, string validateUrl, string sessionName, string responseAccept = "application/json")
        {
            return AddMvcAuthentication(services, redirectUrl, validateUrl, sessionName, typeof(DefaultCASResponseHandler), responseAccept);
        }
    }
}
