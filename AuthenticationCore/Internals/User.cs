using System.Security.Claims;

namespace AuthenticationCore.Internals
{
    internal sealed class User : IUser
    {
        private readonly string name;
        private readonly ClaimsPrincipal claims;

        public string Name => name;
        public ClaimsPrincipal Claims => claims;

        internal User(string name)
        {
            this.name = name;
        }
    }
}
