using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Moryx.AbstractionLayer.Resources.Endpoints
{
    public static class Permissions
    {
        public const string CanEdit = "CanEdit";
        public const string CanRemove = "CanRemove";
        public const string CanShowAspectConfigurator = "CanShowAspectConfigurator";
        public const string CanAddResource = "CanAddResource";
        public const string CanViewTypeTree = "CanViewTypeTree";
    }

    public class AuthSettings
    {
        public bool Enabled { get; set; }
        public string BaseAddress { get; set; }
        public string RequestUri { get; set; }
        public string CookieName { get; set; }
    }

    public class ResourcesAuthorizationPolicyProvider : DefaultAuthorizationPolicyProvider
    {
        private readonly AuthorizationOptions _options;
        private readonly IConfiguration _configuration;
        private readonly string _bib = "Moryx.Resources";

        public ResourcesAuthorizationPolicyProvider(IOptions<AuthorizationOptions> options, IConfiguration configuration) : base(options)
        {
            _options = options.Value;
            _configuration = configuration;
        }

        public override async Task<AuthorizationPolicy> GetPolicyAsync(string policyName)
        {
            // Check static policies first
            var policy = await base.GetPolicyAsync(policyName);

            if (policy == null && PermissionDefined(policyName))
            {
                policy = new AuthorizationPolicyBuilder()
                    .RequireClaim("Permission", $"{_bib}.{policyName}")
                    .Build();

                // Add policy to the AuthorizationOptions, so we don't have to re-create it each time
                _options.AddPolicy(policyName, policy);
            }
            return policy;
        }

        private bool PermissionDefined(string policyName)
        {
            var fields = typeof(Permissions).GetFields();
            var fieldsWithValue = fields.Where(p => p.GetValue(null).Equals(policyName));
            return fieldsWithValue.Any();
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
