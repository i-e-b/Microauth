using System.Collections.Generic;

namespace Microauth
{
    public class UserMap
    {
        /// <summary>
        /// Default hard-coded list of user accounts.
        /// </summary>
        private static readonly Dictionary<string, UserDetails> _userDetailMap = new Dictionary<string, UserDetails>
        {
            {"dev@example.com", new UserDetails("id-dev-sample", "Developer", "Sample", "dev@example.com")}
        };

        public static bool IsKnown(string? username)
        {
            if (string.IsNullOrWhiteSpace(username)) return false;
            return _userDetailMap.ContainsKey(username);
        }

        public static UserDetails GetDetails(string username)
        {
            return _userDetailMap[username];
        }

        public static string KnownUsers()
        {
            return string.Join(", ", _userDetailMap.Keys);
        }
    }
}