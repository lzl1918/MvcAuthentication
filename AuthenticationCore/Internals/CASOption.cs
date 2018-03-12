using System;
using System.Security.Claims;

namespace AuthenticationCore.Internals
{

    internal sealed class CASOption : ICASOption
    {
        public string RedirectUrl { get; }
        public string ValidateUrl { get; }
        public string SessionName { get; }
        public Type CASResponseHandler { get; }

        public CASOption(string redirectUrl, string validateUrl, string sessionName, Type casResponseHandlerType)
        {
            if (validateUrl == null)
                throw new ArgumentNullException(nameof(validateUrl));

            if (sessionName == null)
                throw new ArgumentNullException(nameof(sessionName));

            if (redirectUrl == null)
                throw new ArgumentNullException(nameof(redirectUrl));

            if (casResponseHandlerType.GetInterface(typeof(ICASResponseHandler).FullName) == null)
                throw new InvalidOperationException($"type {casResponseHandlerType.Name} does not implement interface {typeof(ICASResponseHandler).Name}");

            RedirectUrl = redirectUrl;
            ValidateUrl = validateUrl;
            SessionName = sessionName;
            CASResponseHandler = casResponseHandlerType;
        }
    }
}
