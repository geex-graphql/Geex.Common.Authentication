using System;
using System.Threading;
using System.Threading.Tasks;
using HotChocolate.AspNetCore;
using HotChocolate.AspNetCore.Subscriptions;
using HotChocolate.AspNetCore.Subscriptions.Messages;
using HotChocolate.Execution;
using Microsoft.IdentityModel.Tokens;

namespace Geex.Common.Authentication.Utils
{
    public class SubscriptionAuthInterceptor : ISocketSessionInterceptor
    {
        private readonly GeexJwtSecurityTokenHandler _tokenHandler;
        public TokenValidationParameters TokenValidationParameters { get; }

        public SubscriptionAuthInterceptor(TokenValidationParameters tokenValidationParameters, GeexJwtSecurityTokenHandler tokenHandler)
        {
            _tokenHandler = tokenHandler;
            TokenValidationParameters = tokenValidationParameters;
        }
        public async ValueTask OnCloseAsync(ISocketConnection connection, CancellationToken cancellationToken) { }
        public async ValueTask OnRequestAsync(ISocketConnection connection, IQueryRequestBuilder requestBuilder, CancellationToken cancellationToken) { }

        /* We don't need the above two methods, just this one */
        public async ValueTask<ConnectionStatus> OnConnectAsync(ISocketConnection connection, InitializeConnectionMessage message, CancellationToken cancellationToken)
        {
            try
            {
                var jwtHeader = message.Payload["Authorization"] as string;

                //if (string.IsNullOrEmpty(jwtHeader) || !jwtHeader.StartsWith("Bearer "))
                //    return ConnectionStatus.Reject("Unauthorized");

                if (!jwtHeader.IsNullOrEmpty())
                {
                    var token = jwtHeader.Replace("Bearer ", "");
                    var claimsPrincipal = _tokenHandler.ValidateToken(token, this.TokenValidationParameters, out var parsedToken);
                    connection.HttpContext.User = claimsPrincipal;
                    //if (claims == null)
                    //    return ConnectionStatus.Reject("Unauthoized(invalid token)");
                }

                //// Grab our User ID
                //var userId = claims.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "";

                //// Add it to our HttpContext
                //connection.HttpContext.Items["userId"] = userId;

                // Accept the websocket connection
                return ConnectionStatus.Accept();
            }
            catch (Exception ex)
            {
                // If we catch any exceptions, reject the connection.
                // This is probably not ideal, there is likely a way to return a message
                // but I didn't look that far into it.
                return ConnectionStatus.Reject(ex.Message);
            }
        }
    }
}
