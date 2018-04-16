using AuthenticationCore.Internals.Helpers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Threading.Tasks;

namespace AuthenticationCore.Internals.ResponseResults
{
    internal sealed class HttpCASLogoutRedirectResult : IActionResult
    {
        private readonly string targetOverride;
        internal HttpCASLogoutRedirectResult()
        {

        }
        internal HttpCASLogoutRedirectResult(string target)
        {
            if (string.IsNullOrWhiteSpace(target))
                throw new Exception("cannot set target");
            if (!target.StartsWith('/'))
                throw new Exception("a redirect target must start with '/'");
            targetOverride = target;
        }

        public Task ExecuteResultAsync(ActionContext context)
        {
            HttpContext httpContext = context.HttpContext;
            ICASOption option = httpContext.RequestServices.GetRequiredService<ICASOption>();
            HttpRequest request = httpContext.Request;

            string serviceTarget = null;
            if (targetOverride == null)
            {
                serviceTarget = request.GetDisplayUrl().EscapeAll();
            }
            else
            {
                serviceTarget = $"{request.Scheme}://{request.Host}{request.PathBase}{targetOverride}".EscapeAll();
            }
            string authenticationTarget = $"{option.LogoutUrl}?service={serviceTarget}";
            httpContext.Response.Redirect(location: authenticationTarget, permanent: false);
            return Task.CompletedTask;
        }
    }
}
