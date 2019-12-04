using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace xades
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                String sXMLDocument = "<x c=\"3\"  a=\"1\"  b=\"2\"></x>";
                Console.WriteLine(sXMLDocument);

                XAdES xades = new XAdES("SILVESTRIS GIORGIO");
                String sOutput = xades.Sign(sXMLDocument, true);

                Console.WriteLine(sOutput);

                Console.WriteLine("Press any key to exit...");
                Console.ReadKey();
            }
            catch(Exception ex)
            {
                Console.Error.WriteLine("Exception: " + ex);
            }
        }
    }
}
