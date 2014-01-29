using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Security;

namespace BrockAllen.WebSecurityClaimsHelper
{
    public class OAuthClaimsModule : IHttpModule
    {
        ClaimsCookieHelper cookieHelper = new ClaimsCookieHelper();

        public void Init(HttpApplication context)
        {
            context.PostAuthenticateRequest += OnEnter;
            context.EndRequest += OnLeave;
        }

        void OnEnter(object sender, EventArgs e)
        {
            CheckForClaimsCookie();
        }

        private void CheckForClaimsCookie()
        {
            var principal = ClaimsPrincipal.Current;
            if (principal != null)
            {
                var ctx = HttpContext.Current;
                if (ctx != null)
                {
                    var claims = cookieHelper.Read(ctx);
                    if (claims != null)
                    {
                        var id = new ClaimsIdentity(claims);
                        principal.AddIdentity(id);
                    }
                }
            }
        }
        
        void OnLeave(object sender, EventArgs e)
        {
            var ctx = HttpContext.Current;
            if (ctx != null)
            {
                CheckForFormsLogin(ctx);
                CheckForFormsLogout(ctx);
            }
        }

        private void CheckForFormsLogout(HttpContext ctx)
        {
            if (ctx.User != null && 
                ctx.User.Identity != null &&
                ctx.User.Identity.IsAuthenticated)
            {
                if (ctx.Response.Cookies.AllKeys.Contains(FormsAuthentication.FormsCookieName))
                {
                    var logoutCookie = ctx.Response.Cookies[FormsAuthentication.FormsCookieName];
                    if (logoutCookie != null)
                    {
                        var now = DateTime.UtcNow;
                        if (DateTime.MinValue < logoutCookie.Expires && logoutCookie.Expires < now)
                        {
                            cookieHelper.RemoveCookie(ctx);
                        }
                    }
                }
            }
        }

        private void CheckForFormsLogin(HttpContext ctx)
        {
            if (ctx.User == null || 
                ctx.User.Identity == null ||
                !ctx.User.Identity.IsAuthenticated)
            {
                var formsUsername = ClaimsCookieHelper.ExtractUsernameFromFormsCookie();
                if (!String.IsNullOrWhiteSpace(formsUsername))
                {
                    var claims = cookieHelper.Read(ctx);
                    cookieHelper.Write(ctx, formsUsername, claims);
                }
            }
        }

        public void Dispose()
        {
        }
    }
}
