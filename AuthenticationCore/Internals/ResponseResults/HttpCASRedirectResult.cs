using AuthenticationCore.Internals.Helpers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using System.Threading.Tasks;

namespace AuthenticationCore.Internals.ResponseResults
{

    internal sealed class HttpCASRedirectResult : IActionResult
    {
        public Task ExecuteResultAsync(ActionContext context)
        {
            HttpContext httpContext = context.HttpContext;
            ICASOption option = httpContext.RequestServices.GetRequiredService<ICASOption>();
            HttpRequest request = httpContext.Request;

            string serviceTarget = request.GetDisplayUrl().EscapeAll();
            string authenticationTarget = $"{option.RedirectUrl}?service={serviceTarget}";
            httpContext.Response.Redirect(location: authenticationTarget, permanent: false);
            return Task.CompletedTask;
        }
    }
}
