/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief argument_parser class source code
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "argument_parser.h"
#include "exceptions.h"

/**
 * @brief Constructor sets class variables.
 * @param argc Argc from main.
 * @param argv Argv from main.
 * @param opt_string opt_string in same format as for getopt()
 */
argument_parser::argument_parser(const int& argc, char** argv, const std::string& opt_string) :
    arguments_(std::vector<std::string>(argv + 1, argv + argc)), opt_string_(opt_string)
{
}

/**
 * @brief This method starts parsing arguments similarly like getopt() and saves them to map options.
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
}

/**
 * @brief Inserts option to options map.
 * @param argument Name of option.
 * @param position Position of option.
 * @param value Value of option.
 */
void argument_parser::insert_option(const std::string& argument, const int& position, const std::string& value)
{
    if (!options_.insert(std::make_pair(argument, std::make_pair(position, value))).second)
    {
        throw argument_parsing_error("Bad arguments!");
    }
}

/**
 * @brief Inserts option to options_names (arguments without preceding -x).
 * @param position Position of option.
 * @param value Value of option.
 */
void argument_parser::insert_option(const int& position, const std::string& value)
{
    options_names_.emplace_back(position, value);
}

/**
 * @brief Returns count of all parsed arguments.
 * @return Count of all parsed arguments.
 */
long unsigned argument_parser::count() const
{
    return options_names_.size() + options_.size();
}

/**
 * @brief Checks if options map contains argument.
 * @param argument Option name.
 * @return True if contains else false.
 */
bool argument_parser::contains(const std::string& argument)
{
    return options_.find(argument) != options_.end();
}

/**
 * @brief Returns number of arguments without preceding -x.
 * @return Number of arguments without preceding -x.
 */
long unsigned argument_parser::count_names() const
{
    return options_names_.size();
}

/**
 * @brief Checks if options_names contains name on index.
 * @param index Option index.
 * @return True if contains else false.
 */
bool argument_parser::contains(const size_t& index) const
{
    return options_names_.size() > index;
}

/**
 * @brief Operator for accessing options_names
 * @param index Index of argument without preceding -x
 * @return Pair of position and value
 */
std::pair<int, std::string> argument_parser::operator[](const int& index)
{
    return contains(index) ? options_names_[index] : std::make_pair(0, "");
}

/**
 * @brief Operator for accessing options map.
 * @param argument Argument.
 * @return Pair of position and value.
 */
std::pair<int, std::string> argument_parser::operator[](const std::string& argument)
{
    return contains(argument) ? options_[argument] : std::make_pair(0, "");
}
