using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CoreApi.Authorization.TwoFA.Security
{
    public static class OtpHelper
    {
        private const string OTP_HEADER = "X-OTP";

        public static bool HasValidTotp(this HttpRequest request, string key)
        {
            if (request.Headers.ContainsKey(OTP_HEADER))
            {
                var otp = new StringValues();
                request.Headers.TryGetValue(OTP_HEADER, out otp);

                // We need to check the passcode against the past, current, and future passcodes
                if (!string.IsNullOrWhiteSpace(otp))
                {
                    if (TimeSensitivePassCode.GetListOfOTPs(key).Any(t => t.Equals(otp)))
                    {
                        return true;
                    }
                }
            }
            return false;
        }
    }
}
