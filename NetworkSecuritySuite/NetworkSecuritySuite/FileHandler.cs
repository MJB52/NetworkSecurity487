using System;
using System.Linq;
using System.IO;

namespace NetworkSecurityTools
{
    static class FileHandler
    {
        //write string to file given name
        public static void FileWrite(string message, string fileName)
        {

        }
        //read string from file given name
        public static string FileRead(string fileName)
        {
            string fileContents = File.ReadAllText(fileName);
            fileContents.RemoveWhiteSpace();
            return fileContents;
        }
        private static bool ValidateFile(string fileName)
        {
            if (File.Exists(fileName))
                return true;
            else
                Console.WriteLine("Invalid file name.");
            return false;
        }
        //not really part of filehandling but don't want a new class for one method yet
        public static string RemoveWhiteSpace(this string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return value;
            }
            //returns string without any white space
            return value.ToCharArray()
                        .Where(c => !char.IsWhiteSpace(c))//return c where c is not white space
                        .Select(c => c.ToString()) //return c as a string
                        .Aggregate((a, c) => a + c); //add c to the existing string where a is the existing string and c is the char to be added
        }
    }
}
