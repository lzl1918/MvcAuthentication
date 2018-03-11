using System;
using System.Security.Claims;

namespace AuthenticationCore.Internals
{

    internal sealed class CASOption : ICASOption
    {
        public string RedirectUrl { get; }
        public string ValidateUrl { get; }
        public string SessionName { get; }

        public CASOption(string redirectUrl, string validateUrl, string sessionName)
        {
            if (validateUrl == null)
                throw new ArgumentNullException(nameof(validateUrl));

            if (sessionName == null)
                throw new ArgumentNullException(nameof(sessionName));

            if (redirectUrl == null)
                throw new ArgumentNullException(nameof(redirectUrl));

            RedirectUrl = redirectUrl;
            ValidateUrl = validateUrl;
            SessionName = sessionName;
        }
    }
}
