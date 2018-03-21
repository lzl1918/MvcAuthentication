using System;
using System.Security.Claims;

namespace AuthenticationCore.Internals
{

    internal sealed class CASOption : ICASOption
    {
        public string RedirectUrl { get; }
        public string ValidateUrl { get; }
        public string SessionName { get; }
        public string ResponseAccept { get; }
        public Type ResponseHandler { get; }

        public CASOption(string redirectUrl, string validateUrl, string sessionName, string responseAccept, Type responseHandlerType)
        {
            if (validateUrl == null)
                throw new ArgumentNullException(nameof(validateUrl));

            if (sessionName == null)
                throw new ArgumentNullException(nameof(sessionName));

            if (redirectUrl == null)
                throw new ArgumentNullException(nameof(redirectUrl));

            if (responseAccept == null)
                throw new ArgumentNullException(nameof(responseAccept));

            if (responseHandlerType.GetInterface(typeof(ICASResponseHandler).FullName) == null)
                throw new InvalidOperationException($"type {responseHandlerType.Name} does not implement interface {typeof(ICASResponseHandler).Name}");

            RedirectUrl = redirectUrl;
            ValidateUrl = validateUrl;
            SessionName = sessionName;
            ResponseAccept = responseAccept;
            ResponseHandler = responseHandlerType;
        }
    }
}
