using System.Collections.Generic;

namespace Microauth
{
    public class UserDetails
    {
        public UserDetails(string id, string firstName, string lastName, string email)
        {
            Claims = new Dictionary<string, string>();
            Id = id;
            FirstName = firstName;
            LastName = lastName;
            Email = email;
        }

        // ReSharper disable once CollectionNeverUpdated.Global
        public Dictionary<string, string> Claims { get; }
        public string Id { get; }
        public string FirstName { get; }
        public string LastName { get; }
        public string Email { get; }
    }
}