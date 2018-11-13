/**
 * Project: DNS Lookup nastroj
 *
 * @brief ArgumentParser class source
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include <iostream>
#include "argument_parser.h"
#include "error.h"

/**
 * Constructor sets class variables
 * @param argc argc
 * @param argv argv
 * @param opt_string opt_string in same format as for getopt()
 */
argument_parser::argument_parser(const int& argc, char** argv, const std::string& opt_string)
{
    this->arguments_ = std::vector<std::string>(argv + 1, argv + argc);
    this->opt_string_ = opt_string;
} /**
 * This method starts parsing arguments similarly like getopt() and saves them to map options.
 */
void argument_parser::parse()
{
    std::string option;
    auto position = 1;
    for (auto& argument : arguments_)
    {
        if (!option.empty())
        {
            insert_option(option, position - 1, argument);
            option = "";
        }
        else if (argument[0] == '-')
        {
            if (argument.length() == 2)
            {
                const auto pos = opt_string_.find(argument[1]);
                if (pos != std::string::npos)
                {
                    option = argument[1];
                    if (opt_string_.length() > pos + 1)
                    {
                        if (opt_string_[pos + 1] != ':')
                        {
                            insert_option(option, position, "");
                            option = "";
                        }
                    }
                }
                else
                {
                    throw argument_parsing_error("Bad arguments!");
                }
            }
            else
            {
                throw argument_parsing_error("Bad arguments!");
            }
        }
        else
        {
            insert_option(position, argument);
        }
        position++;
    }
    if (!option.empty())
    {
        throw argument_parsing_error("Bad arguments!");
    }
} /**
 * Inserts option to options map
 * @param argument name of option
 * @param position position of option
 * @param value value of option
 */
void argument_parser::insert_option(const std::string& argument, const int& position, const std::string& value)
{
    if (!options_.insert(std::make_pair(argument, std::make_pair(position, value))).second)
    {
        throw argument_parsing_error("Bad arguments!");
    }
} /**
 * Inserts option to options_names (arguments without preceding -x)
 * @param position position of option
 * @param value value of option
 */
void argument_parser::insert_option(const int& position, const std::string& value)
{
    options_names_.emplace_back(position, value);
} /**
 * Prints all parsed arguments in human readable format
 */
void argument_parser::print_arguments()
{
    for (auto elem : options_)
    {
        std::cout << "argument: " << elem.first << " position: " << elem.second.first << " value: " << elem
                                                                                                       .second.second <<
            std::endl;
    }
    for (auto elem : options_names_)
    {
        std::cout << "position: " << elem.first << " value: " << elem.second << std::endl;
    }
} /**
 * Returns count of all parsed arguments
 * @return count of all parsed arguments
 */
long unsigned argument_parser::count() const
{
    return options_names_.size() + options_.size();
} /**
 * Checks if options map contains argument
 * @param argument option name
 * @return true if contains else false
 */
bool argument_parser::contains(const std::string& argument)
{
    return options_.find(argument) != options_.end();
} /**
 * Returns number of arguments without preceding -x
 * @return number of arguments without preceding -x
 */
long unsigned argument_parser::count_names() const
{
    return options_names_.size();
} /**
 * Checks if options_names contains name on index
 * @param index option index
 * @return true if contains else false
 */
bool argument_parser::contains(const size_t& index) const
{
    return options_names_.size() > index;
} /**
 * Operator for accessing options_names
 * @param index index of argument without preceding -x
 * @return pair of position and value
 */
std::pair<int, std::string> argument_parser::operator[](const int& index)
{
    return contains(index) ? options_names_[index] : std::make_pair(0, "");
} /**
 * Operator for accessing options map
 * @param argument argument
 * @return pair of position and value
 */
std::pair<int, std::string> argument_parser::operator[](const std::string& argument)
{
    return contains(argument) ? options_[argument] : std::make_pair(0, "");
}
