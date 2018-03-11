using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace AuthenticationCore
{
    public enum AuthenticationFailedAction
    {
        KeepUnauthenticated,
        RedirectCAS,
        Return401,
        CustomHandler
    }
}
