﻿using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace AuthenticationCore.Internals.ResponseResults
{
    internal sealed class HttpAuthenticationForbiddenResult : IActionResult
    {
        public Task ExecuteResultAsync(ActionContext context)
        {
            context.HttpContext.Response.StatusCode = 403;
            return Task.CompletedTask;
        }
    }
}
