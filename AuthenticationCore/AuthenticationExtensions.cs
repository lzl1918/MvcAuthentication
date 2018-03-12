using AuthenticationCore.Internals;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Text;

namespace AuthenticationCore
{
    public static class AuthenticationExtensions
    {
        public static IServiceCollection AddMvcAuthentication(this IServiceCollection services, string redirectUrl, string validateUrl, string sessionName, Type casResponseHandler)
        {
            if (casResponseHandler.GetInterface(typeof(ICASResponseHandler).FullName) == null)
                throw new InvalidOperationException($"type {casResponseHandler.Name} does not implement interface {typeof(ICASResponseHandler).Name}");

            services.AddScoped<IAuthenticationResultAccessor, AuthenticationResultAccessor>();
            services.AddScoped<IAuthenticationResult>(s => s.GetService<IAuthenticationResultAccessor>().Result);
            services.AddScoped<IAuthenticationService, AuthenticationService>();
            services.AddSingleton<ICASOption>(new CASOption(redirectUrl, validateUrl, sessionName, casResponseHandler));
            return services;
        }

        public static IServiceCollection AddMvcAuthentication<T>(this IServiceCollection services, string redirectUrl, string validateUrl, string sessionName) where T : ICASResponseHandler
        {
            return AddMvcAuthentication(services, redirectUrl, validateUrl, sessionName, typeof(T));
        }

        public static IServiceCollection AddMvcAuthentication(this IServiceCollection services, string redirectUrl, string validateUrl, string sessionName)
        {
            return AddMvcAuthentication(services, redirectUrl, validateUrl, sessionName, typeof(DefaultCASResponseHandler));
        }
    }
}
