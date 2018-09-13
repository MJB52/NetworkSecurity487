using System;
using System.Collections.Generic;
using System.Text;

namespace NetworkSecurityTools
{
    static class Crypt
    {
        enum Lookup
        {
            a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z
        }
        public static string Decrypt(string message, string key)
        {
            message = message.ToLower();
            int keyLenCount = 0;
            int[] DecryptedMessage = new int[message.Length];
            int storeLetter;
            for (int i = 0; i < message.Length; i++)
            {
                if (keyLenCount > key.Length - 1)
                    keyLenCount = 0;
                storeLetter = (message[i] - 97) - (key[keyLenCount] - 97);
                if (storeLetter < 0)
                    storeLetter += 26;
                //converttostring -> write to file
                DecryptedMessage[i] = storeLetter;
                keyLenCount++;
            }
            return ConvertToString(DecryptedMessage);
        }
        public static string Encrypt(string message, string key)
        {
            message = message.ToLower();
            int keyLenCount = 0;
            int[] EncryptedMessage = new int[message.Length];
            int storeLetter = 0;
            for(int i = 0; i < message.Length; i++)
            {
                if (keyLenCount > key.Length - 1)
                {
                    keyLenCount = 0;
                }
                storeLetter = (message[i] - 97) + (key[keyLenCount] - 97);
                if (storeLetter > 25)
                {
                    storeLetter = storeLetter % 26;
                }
                EncryptedMessage[i] = storeLetter;
                keyLenCount++;
                //converttostring -> write to file
            }
            return ConvertToString(EncryptedMessage).ToUpper();
        }
        public static float GetIOC(string cipherText)
        {
            float total = 0;
            int[] letterCounter = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            //converttoint -> 
            cipherText = cipherText.ToLowerInvariant();
            int[] message = ConvertToInt(cipherText);
            
            //Lookup letter;
            for(int i = 0; i < message.Length; i++)
            {
                letterCounter[message[i]]++;
            }
            foreach(int instance in letterCounter)
            {
                total += instance * (instance - 1);
            }
            return total / (cipherText.Length * (cipherText.Length - 1));
            
        }

        public static int[] ConvertToInt(string message)
        {
            int[] messageInInt = new int[message.Length];
            for (int i = 0; i < message.Length; i++)
            {
                messageInInt[i] = (message[i] - 97);
            }
            return messageInInt;
        }
        public static string ConvertToString(int [] intMessage)
        {
            string message = "";
            for(int i = 0; i< intMessage.Length; i++)
            {
                message += (char)(intMessage[i] + 97);
            }
            return message;
        }

    }
}
