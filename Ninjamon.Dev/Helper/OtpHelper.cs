using Microsoft.Extensions.Primitives;
using Ninjamon.Dev.Otp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Ninjamon.Dev.Helper
{
    public static class OtpHelper
    {
        private const string OTP_HEADER = "X-OTP";

        public static bool HasValidTotp(this Microsoft.AspNetCore.Http.HttpRequest request, string key)
        {
            //request.Headers.ContainsKey()
            //if (request.Headers.Contains(OTP_HEADER))
            //{
            //    string otp = request.Headers.GetValues(OTP_HEADER).First();

            //    // We need to check the passcode against the past, current, and future passcodes

            //    if (!string.IsNullOrWhiteSpace(otp))
            //    {
            //        if (TimeSensitivePassCode.GetListOfOTPs(key).Any(t => t.Equals(otp)))
            //        {
            //            return true;
            //        }
            //    }

            //}
            //return false;
            if (request.Headers.ContainsKey(OTP_HEADER))
            {
                var otp = new StringValues();
                request.Headers.TryGetValue(OTP_HEADER, out otp);
                //string otp = request.Headers.GetValues(OTP_HEADER).First();

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
