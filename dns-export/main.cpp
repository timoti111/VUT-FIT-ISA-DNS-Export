#include <iostream>
#include "argument_parser.h"
#include "dns_export.h"
void print_help();

int main(const int argc, char* argv[])
{
    argument_parser arguments(argc, argv, "r:i:s:t:");
    arguments.parse(); //if (arguments.count_names() ||
    //    (arguments.contains("r") && (arguments.contains("i") || arguments.contains("t"))) ||
    //    ((arguments.contains("s") || arguments.contains("t")) && (arguments.contains("r") == arguments.contains("i"))))
    //{
    //    print_help();
    //    //error.error_exit("Bad arguments!", EXIT_FAILURE);
    //}
    /* else if (!arguments.count())
     {
         print_help();
     }
     else
     {*/
    try
    {
        dns_export dns_export; /*  if (arguments.contains("r"))
		  {
		      dns_export.set_pcap_file(arguments["r"].second);
		  }
		  if (arguments.contains("i"))
		  {
		      dns_export.set_interface(arguments["i"].second);
		  }
		  if (arguments.contains("s"))
		  {
		      dns_export.set_syslog_server(arguments["s"].second);
		  }
		  if (arguments.contains("t"))
		  {
		      dns_export.set_timeout(arguments["t"].second);
		  }*/
        dns_export.set_pcap_file("dns.pcap"); //dns_export.set_interface("test");
        dns_export.start();
    }
    catch (std::exception& e)
    {
    } //}
    return EXIT_SUCCESS;
} /**
 * Prints help
 */
void print_help()
{
    std::cout << "dns-export [-r file.pcap] [-i interface] [-s syslog-server] [-t seconds]" << std::endl;
    std::cout << "  -r - spracuje dany pcap soubor" << std::endl;
    std::cout << "  -i - nacuva na danom sietovom rozhrani a spracovava DNS prevadzku" << std::endl;
    std::cout << "  -s - hostname/ipv4/ipv6 adresa syslog serveru" << std::endl;
    std::cout << "  -t - doba vypoctu statistik, predvolena hodnota 60s" << std::endl;
}
