using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Security;

namespace BrockAllen.WebSecurityClaimsHelper
{
    public class OAuthClaims
    {
        static ClaimsCookieHelper cookieHelper = new ClaimsCookieHelper();

        public static void SetClaimsFromAuthenticationResult(DotNetOpenAuth.AspNet.AuthenticationResult result)
        {
            IEnumerable<Claim> claims = GetClaimsFromAuthenticationResult(result);
            WriteClaimsToResponse(claims);
        }

        private static void WriteClaimsToResponse(IEnumerable<Claim> claims)
        {
            var ctx = HttpContext.Current;
            cookieHelper.Write(ctx, claims);
        }

        private static IEnumerable<Claim> GetClaimsFromAuthenticationResult(DotNetOpenAuth.AspNet.AuthenticationResult result)
        {
            return GetClaimsFromDictionary(result.Provider, result.ExtraData);
        }

        private static IEnumerable<Claim> GetClaimsFromDictionary(string provider, IDictionary<string, string> dictionary)
        {
            List<Claim> claims = new List<Claim>();
            foreach (var key in dictionary.Keys)
            {
                if (IsNonKeyMaterial(key))
                {
                    var value = dictionary[key];
                    var claim = GetClaim(provider, key, value);
                    claims.Add(claim);
                }
            }
            return claims;
        }

        private static bool IsNonKeyMaterial(string key)
        {
            return key != "accesstoken";
        }

        private static Claim GetClaim(string provider, string key, string value)
        {
            var claimType = key;
            switch (key)
            {
                // common
                case "id": claimType = ClaimTypes.NameIdentifier; break;
                case "name": claimType = ClaimTypes.Name; break;
                case "link": claimType = ClaimTypes.Webpage; break;
                case "gender": claimType = ClaimTypes.Gender; break;
                case "username": claimType = (provider == "facebook" ? ClaimTypes.Email : ClaimTypes.Name); break;
                
                // live
                case "firstname": claimType = ClaimTypes.GivenName; break;
                case "lastname": claimType = ClaimTypes.Surname; break;
                
                // facebook
                case "birthday": claimType = ClaimTypes.DateOfBirth; break;
                    
                // google
                case "email": claimType = ClaimTypes.Email; break;
                case "country": claimType = ClaimTypes.Country; break;
                case "firstName": claimType = ClaimTypes.GivenName; break;
                case "lastName": claimType = ClaimTypes.Surname; break;

                // twitter
                case "location": claimType = ClaimTypes.Locality; break;
                case "url": claimType = ClaimTypes.Webpage; break;
                // not mapped: description

                // linked in
                // headline, summary, industry
            }
            return new Claim(claimType, value);
        }
    }
}