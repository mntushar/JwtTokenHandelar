using Blazored.LocalStorage;
using DNE.CS.Inventory.Library.Interface;
using Microsoft.AspNetCore.Components;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;

namespace DNE.CS.Inventory.Library;

public class TokenHandelar : ITokenHandelar
{
    private readonly ILocalStorageService _localStorage;
    private IHttpService _httpService;
    private NavigationManager _navigationManager;

    public TokenHandelar(ILocalStorageService localStorage, IHttpService httpService,
        NavigationManager navigationManager)
    {
        _localStorage = localStorage;
        _httpService = httpService;
        _navigationManager = navigationManager;
    }

    public async Task<ClaimsPrincipal> UserInformation()
    {
        string? accessToken = await GetAccessTokenAsync();

        var identity = new ClaimsIdentity();

        if (accessToken != null)
        {
            var claims = ParseClaimsFromJwt(accessToken);
            if (claims.Any())
            {
                identity = new ClaimsIdentity(claims, "jwt");
            }
        }

        var user = new ClaimsPrincipal(identity);

        return user;
    }

    public ClaimsPrincipal UserInformation(string accessToken)
    {
        var identity = new ClaimsIdentity();

        if (accessToken != null)
        {
            var claims = ParseClaimsFromJwt(accessToken);
            if (claims.Any())
            {
                identity = new ClaimsIdentity(claims, "jwt");
            }
        }

        var user = new ClaimsPrincipal(identity);

        return user;
    }

    public async Task<string?> GetAccessTokenAsync()
    {
        try
        {
            if (AppInformation.AccessTokenName == null) return null;

            string? accessToken = await _localStorage.GetItemAsync<string>(
                AppInformation.AccessTokenName);

            if (accessToken == null) return null;

            bool isValid = CheckTokenIsValid(accessToken);

            if (!isValid)
                accessToken = await GetRefreshAccessTokenAsync();

            return accessToken;
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }
    }

    private static long GetTokenExpirationTime(string token)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = handler.ReadJwtToken(token);
            var tokenExp = jwtSecurityToken.Claims.First(claim => claim.Type.Equals("exp")).Value;
            return long.Parse(tokenExp);
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }
    }

    private static bool CheckTokenIsValid(string token)
    {
        try
        {
            var tokenTicks = GetTokenExpirationTime(token);
            var tokenDate = DateTimeOffset.FromUnixTimeSeconds(tokenTicks);

            TimeZoneInfo localTimeZone = TimeZoneInfo.Local;
            DateTime TokenlocalDateTime = TimeZoneInfo.ConvertTimeFromUtc(tokenDate.DateTime, localTimeZone);

            return (DateTime.Now - TokenlocalDateTime).TotalSeconds >= 30;
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }
    }

    private async Task<string?> GetRefreshAccessTokenAsync()
    {
        string? refreshToken = await RefreshToken();

        if (refreshToken == null) return null;

        string url = _navigationManager.BaseUri;
        url = $"{url}Api/Login/?refreshToken={refreshToken}";

        Library.Interface.HttpResponse refreshAccessToken = await _httpService
            .GetAsync(url);

        if (refreshAccessToken.IsSuccess)
        {
            refreshToken = refreshAccessToken.Data;
            if (AppInformation.AccessTokenName == null
                || refreshToken == null) return null;
            await _localStorage.SetItemAsStringAsync(AppInformation.AccessTokenName,
                refreshToken);

            return refreshAccessToken.Data;
        }

        await ClearTokenAsync();

        return null;
    }

    public async Task SetTokenAsync(string accessToken, string refreshToken)
    {
        if (AppInformation.AccessTokenName == null
            || AppInformation.RefreshTokenName == null) return;

        await ClearTokenAsync();

        await _localStorage.SetItemAsync(AppInformation.AccessTokenName,
                accessToken);
        await _localStorage.SetItemAsync(AppInformation.RefreshTokenName,
                refreshToken);
    }

    public async Task ClearTokenAsync()
    {
        if (AppInformation.AccessTokenName == null
            || AppInformation.RefreshTokenName == null) return;
        await _localStorage.RemoveItemAsync(AppInformation.AccessTokenName);
        await _localStorage.RemoveItemAsync(AppInformation.RefreshTokenName);
    }

    public async Task<string?> RefreshToken()
    {
        if (AppInformation.RefreshTokenName == null) return null;
        return await _localStorage.GetItemAsync<string>(
            AppInformation.RefreshTokenName);
    }

    private static SecurityToken? ReadJwtToken(string jwt)
    {
        var handler = new JwtSecurityTokenHandler();
        return handler.ReadToken(jwt) as JwtSecurityToken;
    }

    private static IEnumerable<Claim> ParseClaimsFromJwt(string jwt)
    {
        try
        {
            var payload = jwt.Split('.');
            if (payload.Length >= 1)
            {
                var jsonBytes = ParseBase64WithoutPadding(payload[1]);
                if (jsonBytes.Any())
                {
                    Dictionary<string, object>? keyValuePairs = JsonSerializer
                    .Deserialize<Dictionary<string, object>>(jsonBytes);

                    if (keyValuePairs != null)
                    {
                        return keyValuePairs
                            .Select(kvp => new Claim(kvp.Key, kvp.Value.ToString()!));
                    }
                }
            }

            return Enumerable.Empty<Claim>();
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }
    }

    private static byte[] ParseBase64WithoutPadding(string base64)
    {
        switch (base64.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
        }
        return Convert.FromBase64String(base64);
    }
}
