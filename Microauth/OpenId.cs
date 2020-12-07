using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

// ReSharper disable InconsistentNaming
// ReSharper disable StringLiteralTypo
// ReSharper disable CommentTypo

namespace Microauth
{
    /*
     Reference material:
     
     Overall   : https://openid.net/connect/
     ID Tokens : https://medium.com/@darutk/understanding-id-token-5f83f50fa02e
     Okta OIDC : https://developer.okta.com/docs/reference/api/oidc/
     
     */
    [ApiController]
    public class OktaHarnessController : ControllerBase
    {
        private static readonly RSA rsa = RSA.Create(2048)!;
        private static string LastNonce = "";

        #region Test harness specific

        /// <summary>
        /// This responds to any unknown URLs, to help with development and diagnostics
        /// </summary>
        [HttpGet("{*pathValue}")]
        public IActionResult Catchall(string pathValue)
        {
            Console.WriteLine("Catchall saw a GET: " + pathValue);
            return NotFound()!;
        }

        /// <summary>
        /// This responds to any unknown URLs, to help with development and diagnostics
        /// </summary>
        [HttpPost("{*pathValue}")]
        [HttpPut("{*pathValue}")]
        public IActionResult CatchallPostPut(string pathValue)
        {
            var buf = new byte[1024];
            using var ms = new MemoryStream();
            int len;
            while ((len = Sync.Run(() => Request!.Body!.ReadAsync(buf, 0, buf.Length))) > 0) ms.Write(buf, 0, len);
            ms.Seek(0, SeekOrigin.Begin);

            Console.WriteLine($"Catchall got a {Request?.Method}: {pathValue}");
            Console.WriteLine(Encoding.UTF8.GetString(ms.ToArray()));
            return NotFound()!;
        }

        #endregion



        [HttpGet("oauth2/default/.well-known/openid-configuration")]
        public IActionResult OidConfig()
        {
            Console.WriteLine("Sending proforma config");
            return Ok(StdForm.OauthConfig())!;
        }

        [HttpGet("oauth2/default/v1/keys")]
        public IActionResult Keys()
        {
            Console.WriteLine("Sending key details");
            var keys = GetKeys();
            return Ok(keys)!;
        }

        [HttpGet("oauth2/default/v1/authorize")]
        [HttpPost("oauth2/default/v1/authorize")]
        public IActionResult Oauth_Authorize([FromQuery(Name = "nonce")] string nonce, string state, string sessionToken)
        {
            LastNonce = nonce;
            if (Request?.Query == null) return BadRequest()!;

            var code = sessionToken; // comes from our log-in, this gets passed to the 'Token' endpoint. It's actually the username.

            Console.WriteLine("Saw AUTHORISE with redirect request to: " + Request.Query["redirect_uri"]);

            var response = Content(StdForm.SignInPage(Request.Query["redirect_uri"].ToString(), state, code), "text/html");

            Response!.Cookies!.Append("JSESSIONID", "DA8BA7309345DC3CA14E39AB25AA2B9C", new CookieOptions {Path = "/", Secure = true, IsEssential = true});
            Response.Cookies.Append("sid", "102JzZhOAGGTYC0xFzzEomUYQ", new CookieOptions {Path = "/", Secure = true, HttpOnly = false, IsEssential = true, SameSite = SameSiteMode.Lax});
            Response.Cookies.Append("t", "default", new CookieOptions {Path = "/", Secure = true, SameSite = SameSiteMode.None});
            return response!;
        }

        [HttpGet("oauth2/default/v1/userinfo")]
        [HttpPost("oauth2/default/v1/userinfo")]
        public IActionResult UserInfo()
        {
            var username = Request?.Cookies?["OktaStubUsername"];
            if (string.IsNullOrWhiteSpace(username)) return BadRequest()!;

            Response?.Cookies?.Delete("OktaStubUsername"); // Remove the temporary cookie set by `Token`
            Console.WriteLine("Sending user info details for " + username);

            var user = UserMap.GetDetails(username);

            return Ok(new
            {
                family_name = user.LastName,
                given_name = user.FirstName,
                locale = "en-US",
                name = $"{user.FirstName} {user.LastName}",
                preffered_username = user.Email,
                sub = user.Id,
                zoneinfo = "America/Los_Angeles"
            })!;
        }


        [HttpGet("oauth2/default/v1/token")]
        [HttpPost("oauth2/default/v1/token")]
        public IActionResult Token([FromForm] string? code)
        {
            if (string.IsNullOrWhiteSpace(code)) { Console.WriteLine("Fail to send token: no code given"); return BadRequest()!; }

            Console.WriteLine("Sending token details for " + code);
            Response?.Cookies?.Append("JSESSIONID", "DA8BA7309345DC3CA14E39AB25AA2B9C", new CookieOptions {Path = "/", Secure = true});
            Response?.Cookies?.Append("OktaStubUsername", code, new CookieOptions {Path = "/", Secure = true, HttpOnly = true}); // this lets us pass the data to `UserInfo`

            if (!UserMap.IsKnown(code))
            {
                Console.WriteLine($"Bad request, unknown user {code}. Expected one of {UserMap.KnownUsers()}");
                return BadRequest("User ID does not exist")!;
            }

            var user = UserMap.GetDetails(code);

            var newAccessToken = CreateJWT(user, true);
            var newIdToken = CreateJWT(user, false, authority: "0oa96230cmZ5aGYyF4x6");
            return Ok(new {token_type = "Bearer", expires_in = 3600, access_token = newAccessToken, scope = "openid profile", id_token = newIdToken})!;
        }

        [HttpGet("oauth2/default/v1/logout")]
        public IActionResult Logout(string post_logout_redirect_uri, string state) // ignored params: [id_token_hint, x-client-SKU, x-client-ver]
        {
            Console.WriteLine("Log-out was requested, returning to " + post_logout_redirect_uri);

            Response?.Cookies?.Delete("TestHookCookie"); // must match `TestBypassMiddleware`
            return Redirect(post_logout_redirect_uri + "?state=" + state)!;
        }

        [HttpGet("api/v1/authn")]
        [HttpPost("api/v1/authn")]
        public IActionResult Auth2([FromBody] LoginModel login)
        {
            // Profile information call
            // This is the first call, and basically is the
            // log-in success/failure result.
            if (string.IsNullOrWhiteSpace(login.username)) return BadRequest()!;

            Response?.Headers?.Add("Content-Type", "application/json");
            Console.WriteLine($"Login request from {login.username} with password {login.password}");

            if (login.password != "correct" || !UserMap.IsKnown(login.username)) return FailedLoginResult();

            return SuccessfulLoginResult(login!.username!);
        }

        #region Support methods

        // ReSharper disable once UnusedMember.Local
        private static string GenerateRSACode()
        {
            var p = rsa.ExportParameters(true);
            return $@"private static byte[] D = Base64UrlEncoder.DecodeBytes(""{Base64UrlEncoder.Encode(p.D)}"");
private static readonly byte[] Exponent = Base64UrlEncoder.DecodeBytes(""{Base64UrlEncoder.Encode(p.Exponent)}"");
private static readonly byte[] Modulus = Base64UrlEncoder.DecodeBytes(""{Base64UrlEncoder.Encode(p.Modulus)}"");
private static readonly byte[] P = Base64UrlEncoder.DecodeBytes(""{Base64UrlEncoder.Encode(p.P)}"");
private static readonly byte[] Q = Base64UrlEncoder.DecodeBytes(""{Base64UrlEncoder.Encode(p.Q)}"");
private static readonly byte[] DP = Base64UrlEncoder.DecodeBytes(""{Base64UrlEncoder.Encode(p.DQ)}"");
private static readonly byte[] DQ = Base64UrlEncoder.DecodeBytes(""{Base64UrlEncoder.Encode(p.DQ)}"");
private static readonly byte[] InverseQ = Base64UrlEncoder.DecodeBytes(""{Base64UrlEncoder.Encode(p.InverseQ)}"");
";
        }

        private string GetKeys()
        {
            var parameters = rsa.ExportParameters(true);
            return @"{
            'keys': [
                {
                    'kty': 'RSA',
                    'alg': 'RS256',
                    'use': 'sig',
                    'e': '" + Base64UrlEncoder.Encode(parameters.Exponent) + @"',
                    'n': '" + Base64UrlEncoder.Encode(parameters.Modulus) + @"'
                }
            ]
        }";
        }

        private string CreateJWT(
            UserDetails user,
            bool access,
            string issuer = "https://localhost:6080/oauth2/default",
            string authority = "api://default",
            int daysValid = 10)
        {
            var signingCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256)
            {
                CryptoProviderFactory = new CryptoProviderFactory {CacheSignatureProviders = false}
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var claims = CreateClaimsIdentitiesAsync(user, access);

            // Create JWToken
            var token = tokenHandler.CreateJwtSecurityToken(issuer: issuer,
                audience: authority,
                subject: claims,
                notBefore: DateTime.UtcNow,
                expires: DateTime.UtcNow.AddDays(daysValid),
                signingCredentials: signingCredentials)!;

            return tokenHandler.WriteToken(token)!;
        }

        private IActionResult FailedLoginResult()
        {
            Console.WriteLine("Rejecting login attempt");
            return Unauthorized(new
            {
                errorCode = "E0000004",
                errorSummary = "Authentication failed",
                errorLink = "E0000004",
                errorId = "random_id"
            })!;
        }

        private IActionResult SuccessfulLoginResult(string loginUsername)
        {
            var userDetails = UserMap.GetDetails(loginUsername);

            Console.WriteLine("Accepting login, with claims = " + string.Join(", ", userDetails.Claims.Select(kvp => kvp.Key + "/" + kvp.Value)));
            return Ok(new
            {
                expiresAt = FutureExpiry(),
                status = "SUCCESS",
                sessionToken = loginUsername, // we use this to route data between auth steps
                _embedded = new
                {
                    user = new
                    {
                        id = userDetails.Id,
                        passwordChanged = DateInThePast(),
                        profile = new
                        {
                            login = loginUsername,
                            firstName = userDetails.FirstName,
                            lastName = userDetails.LastName,
                            locale = "en",
                            timeZone = "Antarctica/McMurdo_Station"
                        }
                    }
                },
                _links = new
                {
                    cancel = new
                    {
                        href = "https://localhost:6080/api/v1/authn/cancel",
                        hints = new
                        {
                            allow = new[] {"POST"}
                        }
                    }
                }
            })!;
        }

        private ClaimsIdentity CreateClaimsIdentitiesAsync(UserDetails user, bool access)
        {
            ClaimsIdentity claimsIdentity = new ClaimsIdentity();

            return access ? GetAccessClaims(user, claimsIdentity) : GetIdClaims(user, claimsIdentity);
        }

        private ClaimsIdentity GetAccessClaims(UserDetails user, ClaimsIdentity claimsIdentity)
        {
            claimsIdentity.AddClaim(new Claim("sub", user.Id));
            claimsIdentity.AddClaim(new Claim("ver", "1"));
            claimsIdentity.AddClaim(new Claim("jit", "AT.PbY2FIGG9VhSlmqVxyBMnoXgNqy4zdCNH50ELFQSNPc"));
            claimsIdentity.AddClaim(new Claim("cid", "0oa96230cmZ5aGYyF4x6"));
            claimsIdentity.AddClaim(new Claim("uid", user.Id));
            claimsIdentity.AddClaim(new Claim("scp", @"[""openid"", ""profile""]"));
            foreach (var customClaim in user.Claims) { claimsIdentity.AddClaim(new Claim(customClaim.Key, customClaim.Value)); }
            return claimsIdentity;
        }

        private ClaimsIdentity GetIdClaims(UserDetails user, ClaimsIdentity claimsIdentity)
        {
            claimsIdentity.AddClaim(new Claim("sub", user.Id));
            claimsIdentity.AddClaim(new Claim("name", $"{user.FirstName} {user.LastName}"));
            claimsIdentity.AddClaim(new Claim("ver", "1"));
            claimsIdentity.AddClaim(new Claim(ClaimTypes.Email, user.Email));
            claimsIdentity.AddClaim(new Claim("amr", "['pwd']"));
            claimsIdentity.AddClaim(new Claim("jti", "ID.SiZtvSqdL38y0U671g1SMvDC4CsDytvrvYOUrIWSs3w"));
            claimsIdentity.AddClaim(new Claim("idp", "00o961pglClGZvir84x6"));
            claimsIdentity.AddClaim(new Claim("nonce", LastNonce));
            claimsIdentity.AddClaim(new Claim("preferred_username", user.Email));
            foreach (var customClaim in user.Claims) { claimsIdentity.AddClaim(new Claim(customClaim.Key, customClaim.Value)); }

            /*Time when the End-User authentication occurred. Its value is a JSON number representing the number of seconds from 1970–01–01T0:0:0Z as measured in UTC until the date/time. When a max_age request is made or when auth_time is requested as an Essential Claim, then this Claim is REQUIRED; otherwise, its inclusion is OPTIONAL. (The auth_time Claim semantically corresponds to the OpenID 2.0 PAPE auth_timeresponse parameter.)*/
            claimsIdentity.AddClaim(new Claim("auth_time", SyntheticAuthTime()));
            return claimsIdentity;
        }

        private string SyntheticAuthTime()
        {
            var at = ((int) (DateTime.Now - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds + 3600).ToString();
            Console.WriteLine("Auth time = " + at);
            return at;
        }


        private string DateInThePast()
        {
            //"2020-04-16T10:18:27.000Z"
            return DateTime.Now.AddMonths(-1).ToString("yyyy-MM-dd") + "T12:34:56.000Z";
        }

        private string FutureExpiry()
        {
            //"2021-05-07T10:06:46.000Z"
            return DateTime.Now.AddYears(1).ToString("yyyy-MM-dd") + "T12:34:56.000Z";
        }

        #endregion
    }
}