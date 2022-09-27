using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
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
                    .RequireClaim("Permission", _bib + '.' + policyName)
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
}
