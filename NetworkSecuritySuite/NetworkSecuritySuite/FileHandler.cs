using System;
using System.Linq;
using System.IO;
/// <summary>
/// NAMES: Justin Glenn and Michael Bauer
/// Class Description: this class is responsible for opening files and sending the data elsewhere. It also containts
///                     an extension to the string class to remove all whitespace from a string. 
/// This code was developed by Justin Glenn and Michael Bauer and is not copied from an outside source
/// </summary>
namespace NetworkSecuritySuite
{
    static class FileHandler
    {
        //write string to file given name not implemented yet but maybe will be used in future..if not - remove
        public static void FileWrite(string message, string fileName)
        {
            throw new NotImplementedException("Method not implemented");

        }
        //read string from file given name
        public static string FileRead(string fileName)
        {
            string fileContents = string.Empty;
            fileName = @"../../../" + fileName;
            if (ValidateFile(fileName))
            {
                fileContents = File.ReadAllText(fileName);
            }
            return fileContents.RemoveWhiteSpace().RemoveNonChars().ToLower();
        }
        private static bool ValidateFile(string fileName)
        {
            if (File.Exists(fileName))
                return true;
            else
                Console.WriteLine("Invalid file name: {0}" , fileName);
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
                        .Aggregate((existing, c) => existing + c); //add c to the existing string where existing is the existing string and c is the char to be added
        }
        public static string RemoveNonChars(this string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return value;
            }
            return value.ToCharArray()
                        .Where(c => char.IsLetter(c))
                        .Select(c => c.ToString())
                        .Aggregate((existing, c) => existing + c);
        }
    }
}
