#include <iostream>
#include "argument_parser.h"
#include "dns_export.h"
#include "syslog.h"
#include "error.h"
void print_help();

int main(const int argc, char* argv[])
{
	try
	{
        argument_parser arguments(argc, argv, "hr:i:s:t:");
        arguments.parse();
        if (arguments.count_names() ||
			arguments.count() > 1 && arguments.contains("h") ||
            (arguments.contains("r") && (arguments.contains("i") || arguments.contains("t"))) ||
            ((arguments.contains("s") || arguments.contains("t")) && (arguments.contains("r") == arguments.contains("i"))))
        {
			throw other_error("Bad arguments!");
        }
		if (arguments.contains("h"))
		{
			print_help();
			return EXIT_SUCCESS;
		}
        dns_export dns_export;
		if (arguments.contains("s"))
		{
			dns_export.set_syslog_server(arguments["s"].second);
		}
		if (arguments.contains("t"))
		{
			dns_export.set_timeout(arguments["t"].second);
		}
        if (arguments.contains("r"))
        {
            dns_export.set_pcap_file(arguments["r"].second);
        }
        if (arguments.contains("i"))
        {
            dns_export.set_interface(arguments["i"].second);
			auto stat_thread = dns_export.start_stat_thread();
			stat_thread.detach();
        }
		if (arguments.count())
		{
			dns_export.start();
		}
    }
    catch (std::exception& e)
    {
		std::cerr << e.what() << std::endl;
		return EXIT_FAILURE;
    }
	catch (...)
	{
		std::cerr << "Unknown exception caught!" << std::endl;
		return EXIT_FAILURE;
	}
    return EXIT_SUCCESS;
} /**
 * Prints help
 */
void print_help()
{
    std::cout << "dns-export [-r file.pcap] [-i interface] [-s syslog-server] [-t seconds] [-h]" << std::endl;
    std::cout << "  -r - spracuje dany pcap soubor" << std::endl;
    std::cout << "  -i - nacuva na danom sietovom rozhrani a spracovava DNS prevadzku" << std::endl;
    std::cout << "  -s - hostname/ipv4/ipv6 adresa syslog serveru" << std::endl;
    std::cout << "  -t - doba vypoctu statistik, predvolena hodnota 60s" << std::endl;
	std::cout << "  -h - vypise napovedu programu" << std::endl;
}
