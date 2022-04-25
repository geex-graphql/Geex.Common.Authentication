﻿using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

using Geex.Common.Abstraction;
using Geex.Common.Abstraction.Authorization;
using Geex.Common.Abstraction.Gql.Inputs;
using Geex.Common.Abstraction.Gql.Types;
using Geex.Common.Abstractions;
using Geex.Common.Authentication.Domain;
using Geex.Common.Authentication.GqlSchemas.Inputs;
using Geex.Common.Authentication.Utils;
using Geex.Common.Identity.Api.Aggregates.Users;
using Geex.Common.Identity.Core.Aggregates.Users;

using HotChocolate;

using MediatR;

using StackExchange.Redis.Extensions.Core;
using StackExchange.Redis.Extensions.Core.Abstractions;

namespace Geex.Common.Authentication
{
    public class AuthenticationMutation : MutationExtension<AuthenticationMutation>
    {
        private readonly IMediator mediator;
        private readonly IEnumerable<IExternalLoginProvider> _externalLoginProviders;
        private readonly GeexJwtSecurityTokenHandler _tokenHandler;
        private readonly UserTokenGenerateOptions _userTokenGenerateOptions;

        public AuthenticationMutation(IMediator mediator,
            IEnumerable<IExternalLoginProvider> externalLoginProviders,
            GeexJwtSecurityTokenHandler tokenHandler,
            UserTokenGenerateOptions userTokenGenerateOptions)
        {
            this.mediator = mediator;
            this._externalLoginProviders = externalLoginProviders;
            this._tokenHandler = tokenHandler;
            this._userTokenGenerateOptions = userTokenGenerateOptions;
        }

        public async Task<UserToken> Authenticate(AuthenticateInput input)
        {
            var users = await mediator.Send(new QueryInput<IUser>());
            var user = users.MatchUserIdentifier(input.UserIdentifier?.Trim()) as User;
            if (user == default || !user.CheckPassword(input.Password))
            {
                throw new BusinessException(GeexExceptionType.NotFound, message: "用户名或者密码不正确");
            }
            if (!user.IsEnable)
            {
                throw new BusinessException(GeexExceptionType.ValidationFailed, message: "用户未激活无法登陆, 如有疑问, 请联系管理员.");
            }
            return UserToken.New(user, LoginProviderEnum.Local, _tokenHandler.CreateEncodedJwt(new GeexSecurityTokenDescriptor(user, LoginProviderEnum.Local, _userTokenGenerateOptions)));
        }

        public async Task<UserToken> ExternalAuthenticate(ExternalAuthenticateInput input)
        {
            var externalLoginProvider = _externalLoginProviders.FirstOrDefault(x => x.Provider == input.LoginProvider);
            if (externalLoginProvider == null)
            {
                throw new BusinessException(GeexExceptionType.NotFound, message: "不存在的登陆提供方.");
            }
            var user = await externalLoginProvider.ExternalLogin(input.Code);
            return UserToken.New(user, input.LoginProvider, _tokenHandler.CreateEncodedJwt(new GeexSecurityTokenDescriptor(user, LoginProviderEnum.Local, _userTokenGenerateOptions)));
        }

        public async Task<bool> CancelAuthentication(
            [Service] IRedisDatabase redis,
            [Service] ClaimsPrincipal claimsPrincipal
            )
        {
            var userId = claimsPrincipal?.FindUserId();
            if (!userId.IsNullOrEmpty())
            {
                await redis.RemoveNamedAsync<UserSessionCache>(userId);
                return true;
            }
            return false;
        }
    }
}
