using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Moryx;
using Moryx.AbstractionLayer.Products.Endpoints;
using Moryx.Asp.Integration;

namespace StartProject.Asp
{
    public class Startup
    {
        private readonly IApplicationRuntime _moryxRuntime;
        private string _baseAddress = "https://localhost:5001";

        public Startup(IApplicationRuntime moryxRuntime)
        {
            _moryxRuntime = moryxRuntime;
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

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
             {
                 options.TokenValidationParameters = new TokenValidationParameters
                 {
                     ValidateIssuerSigningKey = true,
                     IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII
                         .GetBytes("veryVerySuperSecretKey")),
                     ValidIssuer = _baseAddress,
                     ValidAudience = _baseAddress,
                     ValidateIssuer = false,
                     ValidateAudience = false
                 };
                 options.Events = new JwtBearerEvents
                 {
                     OnMessageReceived = context =>
                     {
                         context.Token = context.Request.Cookies["user_token"];
                         return Task.CompletedTask;
                     }
                 };
             });

            services.AddAuthorization(options =>
                options.AddPolicy("CanViewTypeTree",
                policy => policy.RequireClaim("Permission", "Moryx.Resources.CanViewTypeTree")));
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
            app.Use(async (context, next) =>
            {
                if (context.User != null && context.User.Identity.IsAuthenticated)
                {
                    var permissions = await GetPermissions(context.Request.Cookies["user_token"]);

                    var appIdentity = new ClaimsIdentity();
                    foreach (var perm in permissions)
                    {
                        appIdentity.AddClaim(new Claim("permission", perm));
                    }
                    context.User.AddIdentity(appIdentity);
                }
                await next();
            });
            app.UseAuthorization();

            // Add MORYX SignalR hubs
            app.UseMoryxProductManagementHub();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }

        private async Task<IEnumerable<string>> GetPermissions(string cookie_value)
        {
            var baseAddress = new Uri(_baseAddress);
            var cookieContainer = new CookieContainer();
            using (var handler = new HttpClientHandler() { CookieContainer = cookieContainer })
            using (var client = new HttpClient(handler) { BaseAddress = baseAddress })
            {
                cookieContainer.Add(baseAddress, new Cookie("user_token", cookie_value));
                var result = await client.GetAsync($"/api/auth/userPermissions");
                if (!result.IsSuccessStatusCode)
                    return null;
                return result.Content.ReadAsAsync<IEnumerable<string>>().Result;
            }
        }
    }
}
