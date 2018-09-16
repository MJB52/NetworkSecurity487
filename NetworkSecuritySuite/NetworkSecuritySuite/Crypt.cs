using System;
using System.Collections.Generic;
using System.Text;
/// <summary>
/// NAMES: Justin Glenn and Michael Bauer
/// Class Description: this class is responsible for encrypting, decrypting, and finding IoC of a block of text. 
///                        it contains a lookup table so that chars can easily be converted to ints and back as ints are easier
///                          to work with. 
/// This code was developed by Justin Glenn and Michael Bauer and is not copied from an outside source
/// </summary>
namespace NetworkSecuritySuite
{
    static class Crypt
    {
        enum Lookup
        {
            a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z
        }
       //                                                    a     b     c     d      e     f    g     h     i     j   k    l     m     n     o     p     q     r    s     t     u      v    w    x     y     z    
        private static readonly double[] FrequencyLookup = { 8.12, 1.49, 2.71, 4.32, 12.02, 2.3, 2.03, 5.92, 7.31, .1, .69, 3.98, 2.61, 6.95, 7.68, 1.82, .11, 6.02, 6.28, 9.10, 2.88, 1.11, 2.09, .17, 2.11, .07};
        //this ^^ contains frequency for each letter in english language
        public static string Decrypt(string message, string key)
        {
            int[] charMessage = ConvertToInt(message.ToLower());
            int[] charKey = ConvertToInt(key.ToLower());
            int[] DecryptedMessage = new int[message.Length];
            int keyLenCount = 0;
            int storeLetter;
            for (int i = 0; i < message.Length; i++)
            {
                if (keyLenCount > key.Length - 1)
                    keyLenCount = 0;
                // storeLetter = (message[i] - 97) - (key[keyLenCount] - 97); //subtract key from cipher  
                storeLetter = charMessage[i] - charKey[keyLenCount];
                if (storeLetter < 0)
                    storeLetter += 26;      // sometimes storeLetter could be less than zero..in this case all that needs to be done is add 26
                //converttostring -> write to file
                DecryptedMessage[i] = storeLetter;
                keyLenCount++;
            }
            return ConvertToString(DecryptedMessage);
        }

        //encyrypt is very similar to decrypt with the exception that it adds the message and the key and then is modded by 26
        public static string Encrypt(string message, string key)
        {
            int [] charMessage = ConvertToInt(message.ToLower());
            int [] charKey = ConvertToInt(key.ToLower());
            int[] EncryptedMessage = new int[message.Length];
            int keyLenCount = 0;
            int storeLetter = 0;
            for(int i = 0; i < message.Length; i++)
            {
                if (keyLenCount > key.Length - 1)
                {
                    keyLenCount = 0;
                }
                //storeLetter = (message[i] - 97) + (key[keyLenCount] - 97); //add key to plaintext 
                storeLetter = charMessage[i] + charKey[keyLenCount];
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
        public static double GetIOC(string cipherText)
        {
            double total = 0;
            int[] letterCounter = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }; //each index kind of represents a index in alphabet
            //converttoint -> 
            cipherText = cipherText.ToLowerInvariant();
            int[] message = ConvertToInt(cipherText);
            
            //Lookup letter;
            for(int i = 0; i < message.Length; i++)
            {
                letterCounter[message[i]]++;    //since message is an int array used like a char array we can actually use message to index our counter
            }
            foreach(int instance in letterCounter)
            {
                total += instance * (instance - 1);     
            }
            return total / (cipherText.Length * (cipherText.Length - 1));
            
        }

        public static void GetSuggestedKeys(string CipherText, int KeyLength)
        {
            int count = 0;
            int keyCount = 0;
            int columnCount = 0;
            string key = "";
            //int letterCount = 0;
            //string[] keysColumn = new string[KeyLength];    
            //string[] likelyKeys = new string[3];        //holds suggested keys..holds 3 keys..could change to more or less
            string[] column = CreateColumns(CipherText, KeyLength); //gets ciphertext into specified columns
            string[] decrypted = new string[26];        //holds each decrypted line 
            foreach(string line in column)
            {
                for(char letter = 'a'; letter <= 'z'; letter++)
                { 
                    decrypted[count] = Decrypt(line, letter.ToString());    //decrypts column26 times for each letter
                    count++; 
                }
                //keysColumn[keyCount] = GetLikelyKeys(decrypted);    //send array of decrypted strings to get likely keys
                key += GetLikelyKeys(decrypted);
                //Console.WriteLine(keysColumn[keyCount].ToString());
                keyCount++;
                count = 0;
            }
            //for (int i = 0; i < likelyKeys.Length; i++)
            //{
            //    //likelyKeys[i] += (keysColumn[columnCount++][i] + keysColumn[columnCount++][i].ToString() + keysColumn[columnCount++][i].ToString() + 
            //    //                    keysColumn[columnCount++][i].ToString() + keysColumn[columnCount][i].ToString()).ToUpper(); //assign Ith char to likelykeys
            //    //columnCount = 0;
            //    for(int j = 0; j < KeyLength; j++)
            //    {
            //        likelyKeys[i] += keysColumn[j][i].ToString().ToUpper();
            //    }
            //}
            //Console.WriteLine("Based on the calculations made, the key is most likely a combination of the following letters: ");
            //foreach(string key in likelyKeys)
            //    Console.WriteLine(key);
            Console.WriteLine(key);
        }       
                                           //each line contains a plaintext message decrypted using each letter of alphabet
        private static string GetLikelyKeys(string [] message)
        {
            string LikelyKey = "";
            char[] arr = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
            double freq, total = 0;
            int count = 0;
            foreach(string line in message)
            {
                freq = FrequencyAnalysis(line);
                    if(freq > total)
                    {
                        //temp = total;
                        //tempKeys = LikelyKeys;
                        total = freq;
                        LikelyKey = arr[count].ToString();
                        //for(int j = i-1 ; j >= 0; j--)
                        //{
                        //    total[j] = temp[j + 1];
                        //    LikelyKeys[j] = tempKeys[j + 1];
                        //}
                    }
                count++;
            }
            return LikelyKey.ToUpper();
        }
        private static double FrequencyAnalysis(string message)
        {
            double total = 0;
            int[] IntMessage = ConvertToInt(message);
            foreach(int letter in IntMessage)
            {
                total += FrequencyLookup[letter];
            }
            return total; 
        }
        public static string [] CreateColumns(string CipherText, int NumColumns)
        {
            string[] columns = new string[NumColumns];
            int index;
            for(int i = 0; i < CipherText.Length; i++)
            {
                index = i % NumColumns;
                columns[index] += CipherText[i].ToString();
            }
            return columns;
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
