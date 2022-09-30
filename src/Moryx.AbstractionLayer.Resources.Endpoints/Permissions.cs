using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Moryx.AbstractionLayer.Resources.Endpoints
{
    public static class ResourcePermissions
    {
        private const string _prefix = "Moryx.Resources.";
        public const string CanEdit = _prefix + "CanEdit";
        public const string CanRemove = _prefix + "CanRemove";
        public const string CanShowAspectConfigurator = _prefix + "CanShowAspectConfigurator";
        public const string CanAddResource = _prefix + "CanAddResource";
        public const string CanViewTypeTree = _prefix + "CanViewTypeTree";
    }

    public class AuthSettings
    {
        public bool Enabled { get; set; }
        public string BaseAddress { get; set; }
        public string RequestUri { get; set; }
        public string CookieName { get; set; }
    }

    public class MoryxAuthorizationPolicyProvider : DefaultAuthorizationPolicyProvider
    {
        private readonly AuthorizationOptions _options;

        public MoryxAuthorizationPolicyProvider(IOptions<AuthorizationOptions> options) : base(options)
        {
            _options = options.Value;
        }

        public override async Task<AuthorizationPolicy> GetPolicyAsync(string policyName)
        {
            // Check static policies first
            var policy = await base.GetPolicyAsync(policyName);

            if (policy == null)
            {
                policy = new AuthorizationPolicyBuilder()
                    .RequireClaim("Permission", policyName)
                    .Build();

                // Add policy to the AuthorizationOptions, so we don't have to re-create it each time
                _options.AddPolicy(policyName, policy);
            }
            return policy;
        }
    }

    public class MoryxAuthHandler : AuthenticationHandler<MoryxAuthSchemeOptions>
    {
        public MoryxAuthHandler(
            IOptionsMonitor<MoryxAuthSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (Context.User == null)
                return AuthenticateResult.Fail("User not found.");

            var userToken = Context.Request.Cookies[Options.CookieName];
            if (userToken == null)
                return AuthenticateResult.Fail("Token not found");

            var permissions = await GetPermissions(userToken);
            // TODO null-check permissions or handle unsuccessfull request
            var appIdentity = new ClaimsIdentity();
            foreach (var perm in permissions)
                appIdentity.AddClaim(new Claim("Permission", perm));
            var ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(appIdentity), this.Scheme.Name);
            return AuthenticateResult.Success(ticket);
        }

        private async Task<IEnumerable<string>> GetPermissions(string cookie_value)
        {
            var baseAddress = new Uri(Options.BaseAdress);
            var cookieContainer = new CookieContainer();
            using (var handler = new HttpClientHandler() { CookieContainer = cookieContainer })
            using (var client = new HttpClient(handler) { BaseAddress = baseAddress })
            {
                cookieContainer.Add(baseAddress, new Cookie(Options.CookieName, cookie_value) { HttpOnly = true });
                var result = await client.GetAsync(Options.RequestUri);
                if (!result.IsSuccessStatusCode)
                    return null;
                return result.Content.ReadAsAsync<IEnumerable<string>>().Result;
            }
        }
    }

    public class MoryxAuthSchemeOptions : AuthenticationSchemeOptions
    {
        public string BaseAdress { get; set; }
        public string CookieName { get; set; }
        public string RequestUri { get; set; }
    }
}
