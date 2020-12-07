using System.Diagnostics.CodeAnalysis;

namespace Microauth
{
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class LoginModel
    {
        // {"password":"y","username":"x","options":{"warnBeforePasswordExpired":true,"multiOptionalFactorEnroll":false}}
        public string? password { get; set; }
        public string? username { get; set; }
    }
}