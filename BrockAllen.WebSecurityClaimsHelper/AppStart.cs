using BrockAllen.WebSecurityClaimsHelper;
using Microsoft.Web.Infrastructure.DynamicModuleHelper;
using System;
using System.Collections.Generic;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Security;

[assembly: PreApplicationStartMethod(typeof(AppStart), "Start")]

namespace BrockAllen.WebSecurityClaimsHelper
{
    public class AppStart
    {
        public static void Start()
        {
            DynamicModuleUtility.RegisterModule(typeof(OAuthClaimsModule));
        }
    }
}
