// See https://aka.ms/new-console-template for more information
using PasswordHashing;
using System.Security.Cryptography;

int parsedInput = -1;
while (parsedInput != 0)
{
    Console.Clear();
    Console.WriteLine("1. New Password");
    Console.WriteLine("2. Use Password");
    Console.WriteLine("3. Encrypt Statement");
    Console.WriteLine("4. View Encrypted Statement");
    Console.WriteLine("5. Decrypt and View Statement");
    Console.WriteLine("\n0. Quit");
    Console.Write("\nMake Selection: ");
    var input = Console.ReadLine();
    int.TryParse(input, out parsedInput);

    if (parsedInput == 1)
    {
        Console.Clear();
        Console.Write("Please enter a new password: ");
        input = Console.ReadLine();

        if (input != null)
        {
            var password = new PasswordMagic(input);
            File.WriteAllText("superSecurePassword.txt", password.PasswordHash);
        }
    }
    else if (parsedInput == 2)
    {
        Console.Clear();
        Console.Write("Please enter the password: ");
        input = Console.ReadLine();

        if (input != null)
        {
            var password = new PasswordMagic(input);
            var passwordHash = File.ReadAllText("superSecurePassword.txt");
            if (password.Validate(passwordHash))
                Console.Write("\n\nAccess Granted");
            else
                Console.Write("\n\nAccess Denied");
            Console.Write(", Press any key to continue...");
            Console.ReadKey();
        }
    }
    else if (parsedInput == 3)
    {
        Console.Clear();
        Console.Write("Please write a statement to encrypt: ");
        input = Console.ReadLine();

        PasswordMagic.GenerateKey(out var key, out var initializationVector);
        File.WriteAllText("AESKey.txt", key);
        File.WriteAllText("AESIV.txt", initializationVector);

        var encryptedText = "";
        if (input != null)
            encryptedText = PasswordMagic.EncryptAES(input, key, initializationVector);

        File.WriteAllText("encrypted.txt", encryptedText);
    }
    else if (parsedInput == 4)
    {
        Console.Clear();
        Console.WriteLine("Encrypted Text: \n");

        var encryptedText = File.ReadAllText("encrypted.txt");
        Console.WriteLine("\n" + encryptedText);

        Console.WriteLine("Press any key to continue...");
        Console.ReadKey();
    }
    else if (parsedInput == 5)
    {
        Console.Clear();
        Console.WriteLine("Encrypted Text: \n");

        var encryptedText = File.ReadAllText("encrypted.txt");
        Console.WriteLine(encryptedText);

        var key = File.ReadAllText("AESKey.txt");
        var initializationVector = File.ReadAllText("AESIV.txt");

        var decryptedText = PasswordMagic.DecryptAES(encryptedText, key, initializationVector);

        Console.WriteLine("\nDecrypted Text: \n");

        Console.WriteLine(decryptedText);

        Console.WriteLine("Press any key to continue...");
        Console.ReadKey();
    }

}