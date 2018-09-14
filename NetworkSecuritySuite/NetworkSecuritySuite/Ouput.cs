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
    static class Ouput
    {
        static public void DisplayText(string message)
        {
            Console.Write("Would you like to display a block of text (1), or display chunks of speicific width (2): ");
            int choice = Int32.Parse(Console.ReadLine());
            if (choice == 1)
            {
                DisplayBlock(message);
                return;
            }
            else if (choice == 2)
            {
                DisplayFormattedColumns(message);
            }
        }
        static private void DisplayFormattedColumns(string message)
        {
            char[] chars = message.ToCharArray();
            int i = 0, width = 0, chunk = 0;

            Console.WriteLine("What is your specified column width: ");
            width = Int32.Parse(Console.ReadLine());

            try
            {
                while (i < message.Length)
                {
                    while (chunk < width)
                    {
                        Console.Write(chars[i + chunk]);
                        chunk++;
                    }
                    i += width;
                    chunk = 0;
                    Console.Write(" ");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("There was an error: " + ex.Message);
            }
        }
        static private void DisplayBlock(string message)
        {
            Console.WriteLine(message);
        }
    }
}
