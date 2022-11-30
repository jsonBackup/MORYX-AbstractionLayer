using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Moryx;
using Moryx.AbstractionLayer.Resources.Endpoints;
using Moryx.Asp.Integration;

namespace StartProject.Asp
{
    public class Startup
    {
        public IConfiguration Configuration { get; }
        private readonly IApplicationRuntime _moryxRuntime;
        private AuthSettings _authSettings;
        public Startup(IApplicationRuntime moryxRuntime, IConfiguration configuration)
        {
            _moryxRuntime = moryxRuntime;
            Configuration = configuration;
        }

        // ConfigureServices() is called by the host before the Configure() method and will configure the app's
        // services. By convention, this where configuration options are set, and where services are added the container.
        // This method is optional for the Startup class.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMoryxFacades(_moryxRuntime);

            services.AddCors(options =>
            {
                options.AddPolicy("CorsPolicy", builder => builder
                .WithOrigins("http://localhost:4200", "http://localhost:4210") // Angular app url for testing purposes
                .AllowAnyMethod()
                .AllowAnyHeader()
                .AllowCredentials());
            });

            services.AddControllers()
               .AddJsonOptions(jo => jo.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter()));

            services.AddSwaggerGen(c =>
            {
                c.CustomOperationIds(api => ((ControllerActionDescriptor)api.ActionDescriptor).MethodInfo.Name);
            });

            // Register AuthSettings
            var authSection = Configuration.GetSection("Auth");
            _authSettings = authSection.Get<AuthSettings>();
            services.Configure<AuthSettings>(authSection);
            services.AddSingleton(_authSettings);

            services.AddAuthentication(options => options.DefaultScheme = "Moryx")
                .AddScheme<MoryxAuthSchemeOptions, MoryxAuthHandler>("Moryx", options =>
                {
                    options.BaseAdress = _authSettings.BaseAddress;
                    options.CookieName = _authSettings.CookieName;
                    options.RequestUri = _authSettings.RequestUri;
                });
            services.AddAuthorization();
            services.AddSingleton<IAuthorizationPolicyProvider, MoryxAuthorizationPolicyProvider>();
        }

        // Configure() is used to specify how the app responds to HTTP requests. The request pipeline is configured
        // by adding middleware components to an IApplicationBuilder instance. IApplicationBuilder is available to the
        // Configure method(), but it isn't registered in the service container. Hosting creates an IApplicationBuilder
        // and passes it directly to Configure().
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();

                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            // Add MORYX UIs

            app.UseRouting();
            if (env.IsDevelopment())
                app.UseCors("CorsPolicy");
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                var conventionBuilder = endpoints.MapControllers();
                if (!_authSettings.Enabled)
                    conventionBuilder.WithMetadata(new AllowAnonymousAttribute());
            });
        }
    }
}