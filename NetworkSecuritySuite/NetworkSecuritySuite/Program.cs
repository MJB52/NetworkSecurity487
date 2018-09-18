using System;
/// <summary>
/// NAMES: Justin Glenn and Michael Bauer
/// Class Description: this is simply the main and is only responsible for calling the menu
/// This code was developed by Justin Glenn and Michael Bauer and is not copied from an outside source
/// </summary>
namespace NetworkSecuritySuite
{
    class Program
    {
        static void Main()
        {
            Console.SetWindowSize(170, Console.WindowHeight);
            Menu menu = new Menu();
            menu.DisplayHelp();
            string choice = menu.GetChoice();
            while(choice != "exit")
            {
               choice = menu.GetChoice();
            }

        }
    }
}
