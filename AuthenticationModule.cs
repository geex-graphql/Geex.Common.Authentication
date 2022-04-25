using System;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Threading.Tasks;

using Geex.Common.Abstractions;
using Geex.Common.Authentication.Domain;
using Geex.Common.Authentication.Utils;
using Geex.Common.Identity.Api.Aggregates.Users;

using HotChocolate.AspNetCore;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

using Volo.Abp;
using Volo.Abp.DependencyInjection;
using Volo.Abp.Modularity;

namespace Geex.Common.Authentication
{
    [DependsOn(
        typeof(GeexCoreModule)
    )]
    public class AuthenticationModule : GeexModule<AuthenticationModule>
    {
        public override void ConfigureServices(ServiceConfigurationContext context)
        {
            IdentityModelEventSource.ShowPII = true;
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
            var services = context.Services;
            services.AddTransient<IPasswordHasher<IUser>, PasswordHasher<IUser>>();
            var moduleOptions = services.GetSingletonInstance<AuthenticationModuleOptions>();
            var tokenValidationParameters = new TokenValidationParameters
            {
                // 签名键必须匹配!
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(moduleOptions.SecurityKey)),

                // 验证JWT发行者(iss)的 claim
                ValidateIssuer = true,
                ValidIssuer = moduleOptions.ValidIssuer,

                // Validate the JWT Audience (aud) claim
                ValidateAudience = true,
                ValidAudience = moduleOptions.ValidAudience,

                // 验证过期
                ValidateLifetime = true,

                // If you want to allow a certain amount of clock drift, set that here
                ClockSkew = TimeSpan.Zero
            };
            services.AddSingleton<TokenValidationParameters>(tokenValidationParameters);
            services.AddSingleton<GeexJwtSecurityTokenHandler>();
            services.AddSingleton<ISocketSessionInterceptor, SubscriptionAuthInterceptor>(x => new SubscriptionAuthInterceptor(x.GetApplicationService<TokenValidationParameters>(), x.GetApplicationService<GeexJwtSecurityTokenHandler>()));
            SchemaBuilder.AddSocketSessionInterceptor(x => new SubscriptionAuthInterceptor(x.GetApplicationService<TokenValidationParameters>(), x.GetApplicationService<GeexJwtSecurityTokenHandler>()));

            services
                .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = tokenValidationParameters;
                    options.SecurityTokenValidators.Clear();
                    options.SecurityTokenValidators.Add(services.GetRequiredServiceLazy<GeexJwtSecurityTokenHandler>().Value);
                    options.Events ??= new JwtBearerEvents();
                    options.Events.OnMessageReceived = receivedContext =>
                    {
                        if (receivedContext.HttpContext.WebSockets.IsWebSocketRequest)
                        {
                            if (receivedContext.HttpContext.Items.TryGetValue("jwtToken", out var token))
                            {
                                receivedContext.Token = token.ToString();
                            }
                        }
                        return Task.CompletedTask;
                    };
                    options.Events.OnAuthenticationFailed = receivedContext => { return Task.CompletedTask; };
                    options.Events.OnChallenge = receivedContext => { return Task.CompletedTask; };
                    options.Events.OnForbidden = receivedContext => { return Task.CompletedTask; };
                    options.Events.OnTokenValidated = receivedContext => { return Task.CompletedTask; };
                });
            services.AddSingleton(new UserTokenGenerateOptions(moduleOptions.ValidIssuer, moduleOptions.ValidAudience, moduleOptions.SecurityKey, TimeSpan.FromSeconds(moduleOptions.TokenExpireInSeconds)));
            services.AddScoped<IClaimsTransformation, GeexClaimsTransformation>();
            base.ConfigureServices(context);
        }

        public override Task OnPreApplicationInitializationAsync(ApplicationInitializationContext context)
        {
            var app = context.GetApplicationBuilder();
            app.UseAuthentication();
            return base.OnPreApplicationInitializationAsync(context);
        }
    }
}
