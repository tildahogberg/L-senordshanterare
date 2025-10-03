using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Buffers.Text;
using System.Linq.Expressions;
using System.Net.Http.Json;
using System.Runtime.Intrinsics.Arm;


namespace Lösenordshanterare
{
    public class Program
    {
        static public void Main(string[] args)
        {
            try
            {
                if (args.Length < 1)
                    Console.WriteLine("Ange ditt kommando.");
                
                else if (args[0] == "init")
                {
                    if (args.Length < 3)
                    {
                        Console.WriteLine("Var vänlig ange alla argument för init.");
                        return;
                    }
                        
                    string clientfile = args[1];
                    string serverfile = args[2];
                    Init(clientfile, serverfile);
                }
                else if (args[0] == "create")
                {
                    if (args.Length < 3)
                    {
                        Console.WriteLine("Var vänlig ange alla argument för create.");
                        return;
                    }

                    string clientfile = args[1];
                    string serverfile = args[2];
                    Create(clientfile, serverfile);
                }
                else if (args[0] == "get")
                {
                    if (args.Length < 3)
                    {
                        Console.WriteLine("Var vänlig ange alla argument för get.");
                        return;
                    }

                    string clientfile = args[1];
                    string serverfile = args[2];
                    string? prop = args.Length >= 4 ? args[3] : null;
                    Get(clientfile, serverfile, prop);
                }
                else if (args[0] == "set")
                {
                    if (args.Length < 4)
                    {
                        Console.WriteLine("Var vänlig ange alla argument för set.");
                        return;
                    }

                    string clientfile = args[1];
                    string serverfile = args[2];
                    string prop = args[3];
                    bool generate;
                    if (args.Length >= 5 && (args[4] == "-g" || args[4] == "--generate"))
                    {
                        generate = true;
                    }
                    else
                        generate = false;

                    Set(clientfile, serverfile, prop, generate);
                }
                else if (args[0] == "delete")
                {
                    if (args.Length < 4)
                    {
                        Console.WriteLine("Var vänlig ange alla argument för delete.");
                        return;
                    }

                    string clientfile = args[1];
                    string serverfile = args[2];
                    string prop = args[3];
                    Delete(clientfile, serverfile, prop);
                }
                else if (args[0] == "secret")
                {
                    if (args.Length < 2)
                    {
                        Console.WriteLine("Var vänlig ange alla argument för secret.");
                        return;
                    }

                    string clientfile = args[1];
                    Secret(clientfile);
                }

            }

            catch 
            {
                Console.WriteLine("En av filerna du angivit finns ej!");
            }

        }

        public static void Init(string clientfile, string serverfile)
        {
            Console.WriteLine("Huvudlösenord: ");
            string masterpwd = Console.ReadLine();
            if (masterpwd == null)
            {
                Console.WriteLine("Ej giltigt lösenord");
                return;
            }


            byte[] secretkey = Encryption.GenerateSecretKey();
            Console.WriteLine(Convert.ToBase64String(secretkey));
            Dictionary<string, byte[]> client = new Dictionary<string, byte[]>();
            client.Add("Secretkey", secretkey);
            string serializedClient = JsonSerializer.Serialize(client);
            File.WriteAllText(clientfile, serializedClient);

            byte[] IV = Encryption.GenerateIV();
            byte[] vaultKey = Encryption.CreateKey(masterpwd, secretkey);

            Dictionary<string, string> Vault = new Dictionary<string, string>();
            string serializedVault = JsonSerializer.Serialize(Vault);
            byte[] EncryptedVault = Encryption.Encrypt(serializedVault, vaultKey, IV);
            ServerFile serverFile = new ServerFile(IV, EncryptedVault);
            string serializedServer = JsonSerializer.Serialize(serverFile);
            File.WriteAllText(serverfile, serializedServer);
        }

        static void Create(string clientfile, string serverpath)
        {
            Console.WriteLine("Skriv in huvudlösenord: ");
            string masterpwd = Console.ReadLine();
            if (masterpwd == null)
            {
                Console.WriteLine("Fel huvudlösenord");
                return;
            }

            Console.WriteLine("Skriv in din personliga nyckel: ");
            string InputSecretkey = Console.ReadLine();
            if (InputSecretkey == null)
            {
                Console.WriteLine("Fel personligt lösenord");
                return;
            }

            InputSecretkey = InputSecretkey.Trim();

            string serializedServerfile = File.ReadAllText(serverpath);

            ServerFile DeServerFile = JsonSerializer.Deserialize<ServerFile>(serializedServerfile);


            try
            {
                byte[] iv = DeServerFile.IV;

                byte[] vaultKey = Encryption.CreateKey(masterpwd, Convert.FromBase64String(InputSecretkey));

                string serializedVault = Encryption.Decrypt(DeServerFile.EncryptedVault, vaultKey, DeServerFile.IV);


                Dictionary<string, byte[]> client = new Dictionary<string, byte[]>();
                client.Add("Secretkey", Convert.FromBase64String(InputSecretkey));
                string serializedClient = JsonSerializer.Serialize(client);
                File.WriteAllText(clientfile, serializedClient);
            }
            catch
            {
                Console.WriteLine("Dekrypteringen misslyckades: ");
            }
        }

        static void Get(string clientfile, string serverfile, string? prop)
        {
            Console.WriteLine("Huvudlösenord: ");
            string? masterpwd = Console.ReadLine();
            if (masterpwd == null) 
            {
                Console.WriteLine("Fel uppstod när huvudlösenordet skulle läsas in");
                return;
            }

            Dictionary<string, string> vault = ReadVault(clientfile, serverfile, masterpwd, null);
            if (vault == null)
                return;

            if (prop != null)
            {
                if (vault.TryGetValue(prop, out string? pass))
                {
                    if (pass != null)
                    {
                        Console.WriteLine(pass);
                    }
                }
            }

            else
            {
                foreach (string p in vault.Keys)
                {
                    Console.WriteLine(p);
                }
            }
        }

        public static Dictionary<string, string> ReadVault(string clientfile, string serverfile, string masterpwd, byte[]? secretkey)
        {
            if (secretkey == null)
            {
                secretkey = ReadSKey(clientfile);
            }

            string serializedServerfile = File.ReadAllText(serverfile);
            ServerFile DeServerFile = JsonSerializer.Deserialize<ServerFile>(serializedServerfile);
            byte[] iv = DeServerFile.IV;

            byte[] vaultKey = Encryption.CreateKey(masterpwd,secretkey);
            string serializedVault = Encryption.Decrypt(DeServerFile.EncryptedVault, vaultKey, DeServerFile.IV);
            Dictionary<string, string> Vault = JsonSerializer.Deserialize<Dictionary<string, string>>(serializedVault);
            return Vault;

        }

        public static void Set(string clientfile, string serverfile, string prop, bool generate)
        {
            Console.WriteLine("Huvudlösenord: ");
            string? masterpwd = Console.ReadLine();
            if (masterpwd == null)
            {
                Console.WriteLine("Fel uppstod när huvudlösenordet skulle läsas in");
                return;
            }


            byte[] secretkey = ReadSKey(clientfile);

            string serializedServerfile = File.ReadAllText(serverfile);

            ServerFile DeServerFile = JsonSerializer.Deserialize<ServerFile>(serializedServerfile);
                byte[] iv = DeServerFile.IV;

            Dictionary<string, string> vault = ReadVault(clientfile, serverfile, masterpwd, secretkey);

            if (vault == null)
                return;

            if (generate)
            {
                string generatepwd = GeneratePwd();
                vault[prop] = generatepwd;
                Console.WriteLine(generatepwd);
            }
            else
            {
                vault[prop] = NewPwd();
            }

            SaveVault(vault, clientfile, serverfile, secretkey, iv, masterpwd);

        }

        public static void SaveVault(Dictionary<string, string> vault, string clientfile, string serverfile, byte[] secretkey, byte[] iv, string masterpassword)
        {
           
            Dictionary<string, byte[]> client = new Dictionary<string, byte[]>();
            client.Add("Secretkey", secretkey);
            string serializedClient = JsonSerializer.Serialize(client);
            File.WriteAllText(clientfile, serializedClient);


            byte[] vaultKey = Encryption.CreateKey(masterpassword, secretkey);

            string serializedVault = JsonSerializer.Serialize(vault);
            byte[] EncryptedVault = Encryption.Encrypt(serializedVault, vaultKey, iv);
            ServerFile serverFile = new ServerFile(iv, EncryptedVault);
            string serializedServer = JsonSerializer.Serialize(serverFile);
            File.WriteAllText(serverfile, serializedServer);
        }

        

         static string NewPwd()
        {
            Console.WriteLine("Vänligen skriv ditt nya lösenord: ");
            string newPwd = Console.ReadLine();
            if(newPwd == null)
            {
                return "";
            }
            return newPwd;
        }

        public static string GeneratePwd()
        {
            using RandomNumberGenerator rng = RandomNumberGenerator.Create();
            byte[] Gnumbers = new byte[20];
            rng.GetBytes(Gnumbers);
            string password = "";
            foreach(byte a in Gnumbers)
            {
                password += ByteChar(a);
               
            }
            return password;
        }

        public static void Delete(string clientfile, string serverfile, string prop)
        {
            Console.WriteLine("Huvudlösenord: ");
            string? masterpwd = Console.ReadLine();
            if (masterpwd == null)
            {
                Console.WriteLine("Fel uppstod när huvudlösenordet skulle läsas in");
                return;
            }

            byte[] secretkey = ReadSKey(clientfile);

            string serializedServerfile = File.ReadAllText(serverfile);

            ServerFile DeServerFile = JsonSerializer.Deserialize<ServerFile>(serializedServerfile);
            byte[] iv = DeServerFile.IV;

            Dictionary<string, string> vault = ReadVault(clientfile, serverfile, masterpwd, secretkey);
            if (vault == null)
                return;

            if (vault.ContainsKey(prop))
            {
                vault.Remove(prop);
            }
            else
            {
                Console.WriteLine("Det gick inte att radera!");
                return;
            }

            
            SaveVault(vault, clientfile, serverfile, secretkey, iv, masterpwd);

        }

        public static void Secret(string clientfile)
        {
            byte[] secretkey = ReadSKey(clientfile);
            Console.WriteLine(Convert.ToBase64String(secretkey));
        }

        public static byte[] ReadSKey(string clientfile)
        {
            try
            {
                string serializedClientfile = File.ReadAllText(clientfile);
                Dictionary<string, byte[]> DeClientFile = JsonSerializer.Deserialize<Dictionary<string, byte[]>>(serializedClientfile);
                return DeClientFile["Secretkey"];
            }
            catch
            {
                Console.WriteLine("Läsning av information misslyckades:(");
                return null;
            }
        }

        static char ByteChar(byte a)
         {
             int aInRange = a % 62;
             if (aInRange < 26)
                 return (char)(aInRange + 'a');
             if (aInRange < 26 * 2)
                 return (char)(aInRange - 26 + 'A');
             return (char)(aInRange - 26 * 2 + '0');
         }

    }
}