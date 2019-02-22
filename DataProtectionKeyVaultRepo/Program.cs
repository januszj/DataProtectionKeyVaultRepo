using System;
using System.IO;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;

namespace DataProtectionKeyVaultRepo
{
    class Program
    {
        //Replace with your azure client id and secret from app that has access to Key Vault
        static readonly string ClientId = "";
        static readonly string ClientSecret = "";

        static void Main(string[] args)
        {
            //Replace with your Azure key and vault name
            var existingKeyName = "";
            var existingVaultName = "";

            //this is for test - this can be any text 
            var anyVaultName = "blaBla";
            var anyKeyName = "blaBla";

            var currentDirectory = Directory.GetCurrentDirectory();


            IDataProtector protector = DataProtectionWithKeyVault(currentDirectory, existingVaultName, existingKeyName);

            Console.Write("Enter input: ");
            var input = Console.ReadLine();

            // Protect the payload
            var protectedPayload = protector.Protect(input);
            Console.WriteLine($"Protect returned: {protectedPayload}");

            // Unprotect the payload
            IDataProtector protector2 = DataProtectionWithKeyVault(currentDirectory, anyVaultName, anyKeyName);
            var unprotectedPayload = protector2.Unprotect(protectedPayload);
            Console.WriteLine($"Unprotect returned: {unprotectedPayload}");

            Console.WriteLine();
            Console.WriteLine("Press any key...");
            Console.ReadKey();
        }

        private static IDataProtector DataProtectionWithKeyVault(string currentDirectory, string vaultName, string keyName)
        {
            // Instantiate the data protection system at this folder
            var dataProtectionProvider = DataProtectionProvider.Create(
                new DirectoryInfo(currentDirectory),
                configuration =>
                {
                    configuration.ProtectKeysWithAzureKeyVault($"https://{vaultName}.vault.azure.net/keys/{keyName}", ClientId, ClientSecret)
                            .UseCryptographicAlgorithms(
                                new AuthenticatedEncryptorConfiguration()
                                {
                                    EncryptionAlgorithm = EncryptionAlgorithm.AES_256_CBC,
                                    ValidationAlgorithm = ValidationAlgorithm.HMACSHA256
                                });
                });

            var protector = dataProtectionProvider.CreateProtector("DataProtectionKeyVaultRepo");
            return protector;
        }
    }
}
