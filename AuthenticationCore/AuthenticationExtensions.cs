using AuthenticationCore.Internals;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Text;

namespace AuthenticationCore
{
    public static class AuthenticationExtensions
    {
        public static IServiceCollection AddMvcAuthentication(this IServiceCollection services, string redirectUrl, string validateUrl, string sessionName)
        {
            services.AddScoped<IAuthenticationResultAccessor, AuthenticationResultAccessor>();
            services.AddScoped<IAuthenticationResult>(s => s.GetService<IAuthenticationResultAccessor>().Result);
            services.AddScoped<IAuthenticationService, AuthenticationService>();
            services.AddSingleton<ICASOption>(new CASOption(redirectUrl, validateUrl, sessionName));
            return services;
        }
    }
}
