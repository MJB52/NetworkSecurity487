using System;
using System.Collections.Generic;
using System.Text;
/// <summary>
/// NAMES: Justin Glenn and Michael Bauer
/// Class Description: this class is to output blocks of text in a certain way. currently it is not used
/// This code was developed by Justin Glenn and Michael Bauer and is not copied from an outside source
/// </summary>
namespace NetworkSecuritySuite
{
    public static class Output
    {
        static public void DisplayText(string message, int keylength = 5)//added default value for now until we have suggested keylength implemented
        {
            Console.Write("Would you like to display a block of text(1), display chunks of speicific width(2), or display columns with ciphertext and plaintext(3): ");
            int choice = Int32.Parse(Console.ReadLine());
            if (choice == 1)
            {
                message.DisplayBlock();
                return;
            }
            else if (choice == 2)
            {
                message.DisplayFormattedColumns();
            }
            else if (choice == 3)
            {
                message.DisplayPartialColumns(keylength);
            }
        }
        static public void DisplayFormattedColumns(this string value)
        {
            char[] chars = value.ToCharArray();
            int i = 0, width = 0, chunk = 0;

            Console.WriteLine("What is your specified column width: ");
            width = Int32.Parse(Console.ReadLine());

            try
            {
                while (i < value.Length)
                {
                    while (chunk < width)
                    {
                        Console.Write(chars[i + chunk]);
                        chunk++;
                    }
                    i += width;
                    chunk = 0;
                    Console.Write(" ");
                    if (Console.CursorLeft == 160)
                    {
                        Console.WriteLine();
                    }
                }
            }
            catch (Exception ex)
            {
                //Console.WriteLine("There was an error: " + ex.Message);
            }
        }
        static public void DisplayBlock(this string value)
        {
            Console.WriteLine(value);
        }

        static public void DisplayPartialColumns(this string value, int keylength) 
        {
            char[] chars = value.ToCharArray();
            int i = 0, j = 0, width = 0, chunk = 0;

            //Console.Write("Would you like to use the assumed keylength(1), give your own keylength(2): ");
            //int choice = Int32.Parse(Console.ReadLine());

            //if (choice == 1)
            //    width = keylength;
            //else if (choice == 2)
            //{
                Console.WriteLine("What is your specified keylength: ");
                width = Int32.Parse(Console.ReadLine());
            //}
            char[] key = new char[width];

            while (i < width)
            {
                Console.Write("What is the specified key for column {0} (if you do not know, enter a space): ", i + 1);
                key[i] = Convert.ToChar(Console.ReadLine());
                i++;
            }

            try
            {
                while (j < value.Length)
                {
                    while (chunk < width)
                    {
                        if (key[chunk].CompareTo(' ') == 0)
                            Console.Write("{0} {1, -3}", chars[j + chunk], '_');
                        else
                            Console.Write("{0} {1, -3}", chars[j + chunk], Crypt.Decrypt(chars[j + chunk].ToString(), key[chunk].ToString()));
                        chunk++;
                    }
                    j += width;
                    chunk = 0;
                    Console.WriteLine();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("There was an error: " + ex.Message);
            }
        }
    }
}
