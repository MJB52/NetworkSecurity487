using System;
using System.IO;
using System.Collections.Generic;
using System.Text;
/// <summary>
/// NAMES: Justin Glenn and Michael Bauer
/// Class Description: this class is our menu class. it grabs user input and depending on that input will process text a certain way
/// This code was developed by Justin Glenn and Michael Bauer and is not copied from an outside source
/// </summary>
namespace NetworkSecuritySuite
{
    class Menu
    {
        public string GetChoice()
        {
            try
            {
                Console.Write("> ");
                return ProcessInput(Console.ReadLine());
            }
            catch (Exception e)
            {
                Console.WriteLine("There was an error.. " + e.Message);
                return "help";
            }
        }
        public void DisplayHelp()
        {
            string ioc = "ic";
            string encrypt = "encrypt";
            string decrypt = "encrypt -d";
            string suggestKeys = "keys";
            string display = "display";
            //string help = "help";
            //Display List of Commands
            Console.WriteLine("The valid commands are\n\t{0} |optionally can be followed by a filename" +
                "              \n\t{1} |optionally can be followed by 2 filenames" +
                "              \n\t{2} |optionally can be follwed by 2 filenames"  +
                "              \n\t{3} |optionally can be followed by filename and a keylength" +
                "              \n\t{4} |optionally can be followed by a filename", ioc, encrypt, decrypt, suggestKeys, display);
        }

        public string ProcessInput(string line)
        {
            //split line by whitespace, look for keywords in each index
            string[] parsed = BreakLine(line);
            if (parsed.Length != 0)
            {
                if (parsed[0].ToLower() == "ic")
                {
                    HandleIC(parsed);
                }
                else if (parsed[0].ToLower() == "encrypt")
                {
                    if (parsed.Length > 1 && parsed[1] == "-d")
                    {
                        HandleDecrypt(parsed);
                    }
                    else
                        HandleEncrypt(parsed);
                }
                else if (parsed[0].ToLower() == "keys")
                {
                    HandleSuggestKeys(parsed);
                }
                else if (parsed[0].ToLower() == "display")
                {
                    HandleDisplay(parsed);
                }
                else if (parsed[0].ToLower() == "exit")
                {

                }
                else
                    DisplayHelp();
                return parsed[0];
            }
            DisplayHelp();
            return "";
        }

        public string[] BreakLine(string line) => line.Split(" ", StringSplitOptions.RemoveEmptyEntries);

        private void HandleSuggestKeys(string [] line)//TODO: discuss what we want user to pass in..file name, filename + keylength? if no keylength is given then ask
        {                                             //       if they would like to specify one or use a suggested one. if no filename is given ask for a block of text
            string flag = "k";
            int keyLength;
            string choice;
            if (line.Length == 3)
            {
                Crypt.GetSuggestedKey(FileHandler.FileRead(line[1]), Convert.ToInt32(line[2]));
            }
            else if (line.Length == 2)
            {
                Console.Write("Would you like to specify a key length(1) or let the program generate one(2)? ");
                choice = Console.ReadLine();
                if (choice == "1")
                {
                    Console.Write("Enter a key length to be used for suggesting keys: ");
                    keyLength = Convert.ToInt32(Console.ReadLine());
                }
                else
                    keyLength = 5; //TODO: REALLY DO THIS: Change to "GetSuggestedKeyLength" when we get it implemented;
                Crypt.GetSuggestedKey(FileHandler.FileRead(line[1]), keyLength);
            }
            else {
                Console.Write("Would you like to specify a key length(1) or let the program generate one(2)? ");
                choice = Console.ReadLine();
                if (choice == "1")
                {
                    Console.Write("Enter a key length to be used for suggesting keys: ");
                    keyLength = Convert.ToInt32(Console.ReadLine());
                }
                else
                    keyLength = 5; //TODO: REALLY DO THIS: Change to "GetSuggestedKeyLength" when we get it implemented;
                Crypt.GetSuggestedKey(GetMessage(flag), keyLength);
                }
        }
        public void HandleDisplay(string [] line) //TODO: discuss what we want user to pass in..file name, filename+ keylength? or not since we ask for it already?
                                                  //       maybe just allow filename or nothing 
        {
            string flag = "d";
            if(line.Length == 2)
            {
                Output.DisplayText(FileHandler.FileRead(line[1]));
            }
            else
            {
                string message = GetMessage(flag);
                Output.DisplayText(message);
            }
        }

        private void HandleEncrypt(string[] line)
        {
            string message, key, flag = "e";
            if(line.Length == 1)
            {
                message = GetMessage(flag);
                key = GetKey(flag);
            }
            else if(line.Length == 2)
            {
                message = FileHandler.FileRead(line[1]);
                key = GetKey(flag);
            }
            else
            {
                message = GetMessage(flag);
                key = GetKey(flag);
            }
            if (message != null && key != null)
                Crypt.Encrypt(message, key).DisplayBlock();
            else
                Console.WriteLine("Message could not be encrypted");
        }

        private void HandleDecrypt(string [] line)
        {
            string message, key, flag = "d";
            if (line.Length == 2)
            {
                message = GetMessage(flag);
                key = GetKey(flag);
            }
            else if(line.Length == 3)
            {
                message = FileHandler.FileRead(line[2]);
                key = GetKey(flag);
            }
            else
            {
                message = GetMessage(flag);
                key = GetKey(flag);
            }
            Crypt.Decrypt(message, key).DisplayBlock();
        }

        private void HandleIC(string [] line)
        {
            double IoC = 0;
            string fileName = "ciphertext.txt";
            if(line.Length == 1)
            {
                IoC = Crypt.GetIOC(FileHandler.FileRead(fileName));
            }
            else
            {
                IoC = Crypt.GetIOC(FileHandler.FileRead(line[1]));
                fileName = line[1];
            }
            Console.WriteLine("Index of Coincedence for data in {0} = {1}",fileName, IoC);
        }

        private string GetKey(string flag)
        {
            string type = "encryption";
            if (flag == "d")
                type = "decryption";
            Console.Write("Enter the key to use for {0}: ", type);
            return Console.ReadLine().ToLower();

        }

        private string GetMessage(string flag)
        {
            string encrypt = "encrypted";
            string decrypt = "decrypted";
            string key = "used for finding keys";
            string display = "displayed";
            string type;
            if (flag == "d")
                type = decrypt;
            else if (flag == "e")
                type = encrypt;
            else if (flag == "k")
                type = key;
            else
                type = display;
            Console.Write("Enter the text to be {0}: ", type);
            return Console.ReadLine();
        }
    }
}
