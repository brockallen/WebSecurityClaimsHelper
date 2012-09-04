using System;
using System.Collections.Generic;
using System.IdentityModel.Services;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.Serialization.Json;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Script.Serialization;
using System.Web.Security;

namespace BrockAllen.WebSecurityClaimsHelper
{
    public class ClaimsCookieHelper
    {
        const string CookieName = "BrockAllen.OAuthClaims";
        const string MachineKeyPurpose = CookieName + ":{0}";
        const string Anonymous = "<Anonymous>";

        public void Write(
            HttpContext context,
            string username,
            IEnumerable<Claim> claims)
        {
            // convert the temp data into json
            string value = Serialize(claims);
            // compress the json -- it really helps
            var bytes = Compress(value);
            // sign and encrypt the data via the asp.net machine key
            value = Protect(bytes, username);
            // issue the cookie
            IssueCookie(context, value);
        }

        public void Write(
           HttpContext context,
           IEnumerable<Claim> claims)
        {
            var username = DetermineUsername(context);
            Write(context, username, claims);
        }

        private string DetermineUsername(HttpContext context)
        {
            var username = context.User.Identity.Name;
            if (String.IsNullOrWhiteSpace(username)) username = ExtractUsernameFromFormsCookie();
            return username;
        }

        internal static string ExtractUsernameFromFormsCookie()
        {
            var ctx = HttpContext.Current;
            if (ctx.Response.Cookies.AllKeys.Contains(FormsAuthentication.FormsCookieName))
            {
                var cookie = ctx.Response.Cookies[FormsAuthentication.FormsCookieName];
                if (cookie != null)
                {
                    var value = cookie.Value;
                    if (!String.IsNullOrWhiteSpace(value))
                    {
                        var ticket = FormsAuthentication.Decrypt(value);
                        if (ticket != null)
                        {
                            var name = ticket.Name;
                            return name;
                        }
                    }
                }
            }
            return null;
        }

        public IEnumerable<Claim> Read(HttpContext context)
        {
            // get the cookie
            var value = GetCookieValue(context);
            // verify and decrypt the value via the asp.net machine key
            var bytes = Unprotect(value, context);
            // decompress to json
            value = Decompress(bytes);
            // convert the json back to a dictionary
            return Deserialize(value);
        }

        string GetCookieValue(HttpContext context)
        {
            if (context.Request.Cookies.AllKeys.Contains(CookieName))
            {
                HttpCookie c = context.Request.Cookies[CookieName];
                if (c != null)
                {
                    return c.Value;
                }
            }
            return null;
        }

        void IssueCookie(HttpContext context, string value)
        {
            // if we don't have a value and there's no prior cookie then exit
            if (value == null)
            {
                if (context.Request.Cookies.AllKeys.Contains(CookieName))
                {
                    RemoveCookie(context);
                }
            }
            else
            {
                context.Response.Cookies.Remove(CookieName);

                HttpCookie c = CreateCookie(context, value);
                context.Response.Cookies.Add(c);
            }
        }

        private static HttpCookie CreateCookie(HttpContext context, string value)
        {
            HttpCookie c = new HttpCookie(CookieName, value)
            {
                // don't allow javascript access to the cookie
                HttpOnly = true,
                // set the path so other apps on the same server don't see the cookie
                Path = context.Request.ApplicationPath,
                // ideally we're always going over SSL, but be flexible for non-SSL apps
                Secure = context.Request.IsSecureConnection
            };
            return c;
        }

        string GetMachineKeyPurpose(string username)
        {
            if (String.IsNullOrWhiteSpace(username)) username = Anonymous;
            return String.Format(MachineKeyPurpose, username);
        }

        string Protect(byte[] data, string username)
        {
            if (data == null || data.Length == 0) return null;

            var purpose = GetMachineKeyPurpose(username);
            var value = MachineKey.Protect(data, purpose);
            return Convert.ToBase64String(value);
        }

        byte[] Unprotect(string value, HttpContext ctx)
        {
            if (String.IsNullOrWhiteSpace(value)) return null;

            var purpose = GetMachineKeyPurpose(ctx.User.Identity.Name);
            var bytes = Convert.FromBase64String(value);
            return MachineKey.Unprotect(bytes, purpose);
        }

        byte[] Compress(string value)
        {
            if (value == null) return null;

            var data = Encoding.UTF8.GetBytes(value);
            using (var input = new MemoryStream(data))
            {
                using (var output = new MemoryStream())
                {
                    using (Stream cs = new DeflateStream(output, CompressionMode.Compress))
                    {
                        input.CopyTo(cs);
                    }

                    return output.ToArray();
                }
            }
        }

        string Decompress(byte[] data)
        {
            if (data == null || data.Length == 0) return null;

            using (var input = new MemoryStream(data))
            {
                using (var output = new MemoryStream())
                {
                    using (Stream cs = new DeflateStream(input, CompressionMode.Decompress))
                    {
                        cs.CopyTo(output);
                    }

                    var result = output.ToArray();
                    return Encoding.UTF8.GetString(result);
                }
            }
        }

        string Serialize(IEnumerable<Claim> claims)
        {
            if (claims == null || !claims.Any()) return null;

            var ser = CreateSerializer();
            using (var ms = new MemoryStream())
            {
                ser.WriteObject(ms, claims);
                ms.Seek(0, SeekOrigin.Begin);
                return Convert.ToBase64String(ms.ToArray());
            }
        }

        IEnumerable<Claim> Deserialize(string data)
        {
            if (String.IsNullOrWhiteSpace(data)) return null;

            var ser = CreateSerializer();
            using (var ms = new MemoryStream(Convert.FromBase64String(data)))
            {
                return (IEnumerable<Claim>)ser.ReadObject(ms);
            }
        }

        DataContractJsonSerializer CreateSerializer()
        {
            return new DataContractJsonSerializer(typeof(IEnumerable<Claim>));
        }

        public void RemoveCookie(HttpContext context)
        {
            context.Response.Cookies.Remove(CookieName);
            HttpCookie c = CreateCookie(context, ".");
            c.Expires = DateTime.UtcNow.AddMonths(-1);
            context.Response.Cookies.Add(c);
        }
    }
}
