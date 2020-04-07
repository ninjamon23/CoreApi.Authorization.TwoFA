using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CoreApi.Authorization.TwoFA.Security
{
    public class TwoFactorAuthFilter : IActionFilter
    {
        public void OnActionExecuted(ActionExecutedContext context)
        {
        }

        public void OnActionExecuting(ActionExecutingContext context)
        {
            var principal = context.HttpContext.User;
            var preSharedKey = principal.FindFirst("PSK").Value;
            bool hasValidTotp = OtpHelper.HasValidTotp(context.HttpContext.Request, preSharedKey);

            if (!hasValidTotp)
            {
                context.Result = new ObjectResult("OTP InValid") { StatusCode = 401 };
            }
        }
    }
}
