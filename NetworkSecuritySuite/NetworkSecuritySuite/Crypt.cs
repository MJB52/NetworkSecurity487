using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
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
            a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z
        }
        //                                                    a     b     c     d      e     f    g     h     i     j   k    l     m     n     o     p     q     r    s     t     u      v    w    x     y     z    
        private static readonly double[] FrequencyLookup = { 8.12, 1.49, 2.71, 4.32, 12.02, 2.3, 2.03, 5.92, 7.31, .1, .69, 3.98, 2.61, 6.95, 7.68, 1.82, .11, 6.02, 6.28, 9.10, 2.88, 1.11, 2.09, .17, 2.11, .07 };
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
            int[] charMessage = ConvertToInt(message.ToLower());
            int[] charKey = ConvertToInt(key.ToLower());
            int[] EncryptedMessage = new int[message.Length];
            int keyLenCount = 0;
            int storeLetter = 0;
            for (int i = 0; i < message.Length; i++)
            {
                if (keyLenCount > key.Length - 1)
                {
                    keyLenCount = 0;
                }
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
            for (int i = 0; i < message.Length; i++)
            {
                letterCounter[message[i]]++;    //since message is an int array used like a char array we can actually use message to index our counter
            }
            foreach (int instance in letterCounter)
            {
                total += instance * (instance - 1);
            }
            return total / (cipherText.Length * (cipherText.Length - 1));

        }

        public static void GetSuggestedKey(string CipherText, int KeyLength)
        {
            int count = 0;
            string key = string.Empty;
            string[] column = CreateColumns(CipherText, KeyLength); //gets ciphertext into specified columns
            string[] decrypted = new string[26];        //holds each decrypted line 
            foreach (string line in column)
            {
                for (char letter = 'a'; letter <= 'z'; letter++)
                {
                    decrypted[count] = Decrypt(line, letter.ToString());    //decrypts column26 times for each letter
                    count++;
                }
                key += FindKeyForColumn(decrypted);
                count = 0;
            }
            Console.WriteLine(key);
        }
        //each line contains a plaintext message decrypted using each letter of alphabet
        private static string FindKeyForColumn(string[] message)
        {
            string LikelyKey = string.Empty;
            char[] arr = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
            double freq, total = 0;
            int count = 0;
            foreach (string line in message)
            {
                freq = FrequencyAnalysis(line);
                if (freq > total)
                {
                    total = freq;
                    LikelyKey = arr[count].ToString();
                }
                count++;
            }
            return LikelyKey.ToUpper();
        }
        private static double FrequencyAnalysis(string message)
        {
            double total = 0;
            int[] IntMessage = ConvertToInt(message);
            foreach (int letter in IntMessage)
            {
                total += FrequencyLookup[letter];
            }
            return total;
        }
        public static string[] CreateColumns(string CipherText, int NumColumns)
        {
            string[] columns = new string[NumColumns];
            int index;
            for (int i = 0; i < CipherText.Length; i++)
            {
                index = i % NumColumns;
                columns[index] += CipherText[i].ToString();
            }
            return columns;
        }
        public static void FindLikelyKeyLength(string message)
        {
            List<int> value = new List<int>();
            List<int> factors = new List<int>();
            List<int> totalFactors = new List<int>();
            List<KeyValuePair<int, int>> totalFactorsRefined = new List<KeyValuePair<int, int>>();
            List<KeyValuePair<string, int>> Repeats = new List<KeyValuePair<string, int>>();
            string buffer = string.Empty;
            int bufferCount = 0;
            int count = -1;
            int temp = 0;
            for (int j = 10; j >= 2; j--)
            {
                Repeats.AddRange(GetPatterns(message, j).OrderBy(c => c.Value).ToList());
            }
            Console.Write("{0,-11}|{1,-7}|{2,-30}|{3,-23}|{4,-20}", "String", "Count", "Location", "Spacing", "Factors");
            foreach (KeyValuePair<string, int> pair in Repeats)
            {
                if (pair.Value > 1)
                {
                    for (int i = 0; i < pair.Value; i++)
                    {
                        temp = message.IndexOf(pair.Key, count + 1);//gets locations of each occurrence 
                        count = temp;
                        value.Add(count);
                    }
                    count = -1;
                    if (pair.Value > 2) //output flag..gotta have more than 2 occurences for it to show up
                    {
                        Console.WriteLine();
                        Console.Write("{0,-11}|{1,-7}|", pair.Key, pair.Value);
                        foreach (int c in value)
                        {
                            Console.Write(c + " ");
                            bufferCount += (c + " ").ToString().Length;
                        }
                        buffer = string.Concat(Enumerable.Repeat(" ", 30 - bufferCount));//do this to make things look nice.." " gets repeated 30 - buffercount times
                        Console.Write(buffer + "|");
                        buffer = string.Empty;
                        bufferCount = 0;
                    }
                    factors = GetDifference(value, pair.Value).ToList(); //
                    totalFactors.AddRange(factors);
                }
                value.Clear();
            }
            totalFactorsRefined.AddRange(GetOccurences(totalFactors));
            Console.WriteLine();
            Console.WriteLine("----------------------------------------------------------------------------------");
            Console.WriteLine("{0,-19}|{1,-1}", "Likely Key Length", "Likely Key");
            Console.WriteLine("----------------------------------------------------------------------------------");
            List<int> highestFactors = GetHighFactors(totalFactorsRefined, 10); //gets the 10 highest occurring factors
            foreach (int fac in highestFactors)
            {
                Console.Write("{0,-19}|", fac);
                GetSuggestedKey(message, fac);
            }
            Console.WriteLine();
        }
        //gets the X number of common factors that appear most
        private static List<int> GetHighFactors(List<KeyValuePair<int, int>> totalFactorsRefined, int numFacts)
        {
            List<int> HighFacs = new List<int>(numFacts);
            HighFacs = totalFactorsRefined.OrderByDescending(c => c.Value).Select(c => c.Key).ToList();
            HighFacs.RemoveRange(numFacts, HighFacs.Count - numFacts);
            return HighFacs;
        }
        //counts the number of times an item appears in a list returns it as key value pair..key being the number and value being how many times it appears
        private static IEnumerable<KeyValuePair<int, int>> GetOccurences(List<int> newFactors)
        {
            int count = 0;
            List<int> throwAwayList = new List<int>();
            foreach (int f in newFactors)
            {
                for (int i = 0; i < newFactors.Count; i++)
                {
                    if (newFactors[i] == f)
                        count++;
                }
                if (!throwAwayList.Contains(f))
                    yield return new KeyValuePair<int, int>(f, count);
                throwAwayList.Add(f);
                count = 0;
            }
        }
        //counts how many times something appears in a string given a string length
        private static IEnumerable<KeyValuePair<string, int>> GetPatterns(string value, int blockLength)
        {
            string currentBlock = string.Empty;
            string tempBlock = string.Empty;
            int count = 0;
            List<string> list = new List<string>();
            for (int i = 0; i < value.Length; i++)
            {
                if (i + blockLength <= value.Length)
                {
                    currentBlock = value.Substring(i, blockLength);
                    if (!list.Contains(currentBlock))
                    {
                        list.Add(currentBlock);
                        for (int j = 0; j <= value.Length - blockLength; j++)
                        {
                            tempBlock = value.Substring(j, blockLength);
                            if (currentBlock == tempBlock)
                                count++;
                        }
                        yield return new KeyValuePair<string, int>(currentBlock, count);
                    }
                    count = 0;
                }
            }
        }
        //find the difference between two factors..returns hashset
        private static IEnumerable<int> GetDifference(List <int> arr, int outputFlag)//output flag used to only print higher values
        {
            int temp;
            string buffer = string.Empty;
            int bufferCounter = 0;
            HashSet<int> commonFactors = new HashSet<int>();
            for(int i = 0; i < arr.Count - 1; i++)
            {
                temp = arr[i + 1] - arr[i];     //difference betwen nth position and n-1th position
                if (outputFlag > 2)
                {
                    Console.Write(temp + " ");
                    bufferCounter += (temp + " ").ToString().Length;
                }
                commonFactors.UnionWith(GetFactors(temp));//adds new values not repeating values
            }
            if (outputFlag > 2)
            {
                buffer = string.Concat(Enumerable.Repeat(" ", 23 - bufferCounter));
                Console.Write(buffer + "|");
                buffer = string.Empty;
                bufferCounter = 0;
                foreach (int num in commonFactors)
                {
                    Console.Write(num + " ");
                }
            }
            return commonFactors;
        }
        //gets a list of factors from an int..use a hashset to ensure numbers only show up once
        private static HashSet<int> GetFactors(int value) 
        {
            int temp = 1;
            HashSet<int> factors = new HashSet<int>();
            while (temp <= value)
            {
                if (value % temp == 0 && temp != 1 && temp != value)//dont want 1 and value 
                    factors.Add(temp);
                temp++;
            }
            return factors;
        }
        //convert from string to int array
        public static int[] ConvertToInt(string message)
        {
            int[] messageInInt = new int[message.Length];
            for (int i = 0; i < message.Length; i++)
            {
                messageInInt[i] = (message[i] - 97);
            }
            return messageInInt;
        }
        //convert from int array to string
        public static string ConvertToString(int [] intMessage)
        {
            string message = string.Empty;
            for(int i = 0; i< intMessage.Length; i++)
            {
                message += (char)(intMessage[i] + 97);
            }
            return message;
        }

    }
}
