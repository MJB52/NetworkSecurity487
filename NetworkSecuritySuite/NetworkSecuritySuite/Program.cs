using System;
/// <summary>
/// NAMES: Justin Glenn and Michael Bauer
/// Class Description: this is simply the main and is only responsible for calling the menu
/// This code was developed by Justin Glenn and Michael Bauer and is not copied from an outside source
/// </summary>
namespace NetworkSecurityTools
{
    class Program
    {
        static void Main()
        {
            Menu menu = new Menu();
            string choice = menu.GetChoice();
            //Console.WriteLine("This is actually a test boi");
            while(choice != "exit")
            {
               choice = menu.GetChoice();
            }

        }
    }
}
