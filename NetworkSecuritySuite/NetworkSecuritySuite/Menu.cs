using System;
using System.IO;
using System.Collections.Generic;
using System.Text;

namespace NetworkSecurityTools
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
            //string help = "help";
            //Display List of Commands
            Console.WriteLine("The valid commands are\n\t{0} |optionally can be followed by a filename" +
                "              \n\t{1} |optionally can be followed by 2 filenames" +
                "              \n\t{2} |optionally can be follwed by 2 filenames" , ioc, encrypt, decrypt);
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

        public void HandleEncrypt(string[] line)
        {
            string message, key, flag = "e";
            if(line.Length != 3)
            {
                message = GetMessage(flag);
                key = GetKey(flag);
            }
            else{
                message = FileHandler.FileRead(line[1]);
                key = FileHandler.FileRead(line[2]);
            }
            Console.WriteLine(Crypt.Encrypt(message, key));

            
        }
        public void HandleDecrypt(string [] line)
        {
            string message, key, flag = "d";
            if (line.Length != 4)
            {
                message = GetMessage(flag);
                key = GetKey(flag);
            }
            else
            {
                message = FileHandler.FileRead(line[2]);
                key = FileHandler.FileRead(line[3]);
            }
            Console.WriteLine(Crypt.Decrypt(message, key));
        }
        public void HandleIC(string [] line)
        {
            float IoC = 0;
            string fileName;
            if(line.Length == 1)
            {
                IoC = Crypt.GetIOC(FileHandler.FileRead("ciphertext.txt"));
                fileName = "ciphertext.txt";
            }
            else
            {
                IoC = Crypt.GetIOC(FileHandler.FileRead(line[1]));
                fileName = line[1];
            }
            Console.WriteLine("Index of Coincedence for data in {0} = {1}",fileName, IoC);
        }
        public string GetKey(string flag)
        {
            string type = "encryption";
            if (flag == "d")
                type = "decryption";
            Console.Write("Enter the key to use for {0}: ", type);
            return Console.ReadLine().ToLower();

        }
        public string GetMessage(string flag)
        {
            string type = "encrypted";
            if (flag == "d")
                type = "decrypted";
            Console.Write("Enter the text to be {0}: ", type);
            return Console.ReadLine();

        }
    }
}
