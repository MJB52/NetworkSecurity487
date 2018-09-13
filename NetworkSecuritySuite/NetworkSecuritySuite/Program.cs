using System;

namespace NetworkSecurityTools
{
    class Program
    {
        static void Main()
        {
            Menu menu = new Menu();
            string choice = menu.GetChoice();
            while(choice != "exit")
            {
               choice = menu.GetChoice();
            }

        }
    }
}
