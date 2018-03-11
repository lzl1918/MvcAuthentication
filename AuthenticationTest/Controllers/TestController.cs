using AuthenticationCore;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;

namespace AuthenticationTest.Controllers
{
    public class TestController : Controller
    {
        [AuthenticationRequired(failedAction: AuthenticationFailedAction.RedirectCAS)]
        public string Index([FromServices] IAuthenticationResult result)
        {
            if (result.IsAuthenticated)
            {
                return $"hello, {result.User.Name} from index";
            }
            else
                return "hello, index";
        }

        [AuthenticationRequired(failedAction: AuthenticationFailedAction.RedirectCAS)]
        public string Go([FromServices] IAuthenticationResult result)
        {
            return $"hello, {result.User.Name} from go";
        }

        public async Task<IActionResult> No([FromServices] IAuthenticationService service)
        {
            IAuthenticationResult result = await service.CASAsync();
            if (result.IsAuthenticated)
            {
                ContentResult content = new ContentResult();
                content.Content = "hello from no " + result.User.Name;
                return content;
            }
            else
            {
                return service.CreateRedirectCASResult();
            }
        }
    }
}