﻿using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;

using Geex.Common.Abstraction;
using Geex.Common.Abstraction.Authorization;
using Geex.Common.Abstractions.Enumerations;
using Geex.Common.Authentication.Domain;
using Geex.Common.Identity.Core.Aggregates.Users;

using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;

using MongoDB.Entities;

using StackExchange.Redis.Extensions.Core;
using StackExchange.Redis.Extensions.Core.Abstractions;

namespace Geex.Common.Authentication.Utils
{
    public class GeexClaimsTransformation : IClaimsTransformation
    {
        private readonly IEnumerable<ISubClaimsTransformation> _transformations;
        private readonly IRedisDatabase _redis;
        private UserTokenGenerateOptions _options;
        private readonly GeexJwtSecurityTokenHandler _tokenHandler;
        private TokenValidationParameters _validationParams;

        public GeexClaimsTransformation(IEnumerable<ISubClaimsTransformation> transformations, IRedisDatabase redis, UserTokenGenerateOptions options, GeexJwtSecurityTokenHandler tokenHandler, TokenValidationParameters validationParams)
        {
            _transformations = transformations;
            _redis = redis;
            _options = options;
            _tokenHandler = tokenHandler;
            _validationParams = validationParams;
        }



        public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
        {
            var userId = principal.FindUserId();
            if (userId.IsNullOrEmpty())
            {
                return principal;
            }

            var cachedSession = await this._redis.GetNamedAsync<UserSessionCache>(userId);
            ClaimsIdentity claimsIdentity = new ClaimsIdentity();
            if (cachedSession != default)
            {
                claimsIdentity.AppendClaims((_tokenHandler.ReadToken(cachedSession.token) as JwtSecurityToken).Claims);
                principal.AddIdentity(claimsIdentity);
                return principal;
            }

            var user = DB.Queryable<User>().FirstOrDefault(x => x.Id == userId);
            if (user == null)
            {
                return principal;
            }
            var ownedOrgCodes = DB.Queryable<User>().Select(x => new { x.Id, x.OrgCodes }).First(x => x.Id == principal.FindUserId()).OrgCodes;
            foreach (var ownedOrgCode in ownedOrgCodes)
            {
                claimsIdentity.AppendClaims(new Claim(GeexClaimType.Org, ownedOrgCode, valueType: "array"));
            }

            foreach (var transformation in this._transformations)
            {
                var claimsPrincipal = await transformation.TransformAsync(user, principal);
                claimsIdentity.AppendClaims(claimsPrincipal.Claims);
            }

            var tokenDescriptor = new GeexSecurityTokenDescriptor(user, LoginProviderEnum.Local, _options, claimsIdentity.Claims);
            // 设置用户session, 缓存数据10分钟, 避免大量的组织架构和权限查询
            await this._redis.SetNamedAsync(new UserSessionCache { userId = userId, token = _tokenHandler.CreateEncodedJwt(tokenDescriptor) }, expireIn: TimeSpan.FromMinutes(10));
            principal.AddIdentity(claimsIdentity);

            return principal;
        }
    }
}
