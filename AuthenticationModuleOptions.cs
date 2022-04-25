using Geex.Common.Abstractions;

namespace Geex.Common.Authentication
{
    public class AuthenticationModuleOptions : IGeexModuleOption<AuthenticationModule>
    {
        public string ValidIssuer { get; set; }
        public string ValidAudience { get; set; }
        public string SecurityKey { get; set; }
        public double TokenExpireInSeconds { get; set; } = 3600 * 24;
    }
}
