using TokenForge.Domain.Interfaces;
using System;
using System.Text.RegularExpressions;
using TimeZoneConverter;

namespace TokenForge.Application.Common
{
    public class Helpers : IHelpers
    {
        /// <summary>
        /// Gets the current date and time in the Buenos Aires time zone.
        /// </summary>
        public virtual DateTime GetBuenosAiresTime()
        {
            var timeZone = TZConvert.GetTimeZoneInfo("America/Argentina/Buenos_Aires");

            DateTime buenosAiresTime = TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, timeZone);

            return buenosAiresTime;
        }

        /// <summary>
        /// Validates whether the provided email address is in a correct format.
        /// </summary>
        /// <param name="Email">The email address to validate.</param>
        /// <returns>True if the email is valid; otherwise, false.</returns>
        public bool EmailValidator(string Email)
        {
            string Pattern = @"^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$";

            if (string.IsNullOrWhiteSpace(Email))
                return false;

            return Regex.IsMatch(Email, Pattern);
        }
        /// <summary>
        /// Validates whether the provided user account name is valid (alphanumeric and underscores, 1-20 characters).
        /// </summary>
        /// <param name="UserAccount">The user account name to validate.</param>
        /// <returns>True if the account name is valid; otherwise, false.</returns>
        public bool AccountValidator(string UserAccount)
        {
            string Pattern = @"^[a-zA-Z0-9_]{1,20}$";

            if (string.IsNullOrWhiteSpace(UserAccount))
                return false;

            return Regex.IsMatch(UserAccount, Pattern);
        }
        /// <summary>
        /// Validates whether the provided password meets the required criteria (8-32 characters, at least one digit and one special character).
        /// </summary>
        /// <param name="Pass">The password to validate.</param>
        /// <returns>True if the password is valid; otherwise, false.</returns>
        public bool PassValidator(string Pass)
        {
            if (Pass.Length < 8 || Pass.Length > 32)
            {
                return false;
            }
            const string passwordPattern = @"^(?=.*\d)(?=.*[\W_]).{8,32}$";
            return Regex.IsMatch(Pass, passwordPattern);
        }
    }
}

