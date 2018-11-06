/**
 * Project: DNS Lookup nastroj
 *
 * @brief ArgumentParser class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include <map>
#include <string>
#include <vector>

/**
 * This class is for parsing arguments. It is similar as getopt(), but parses arguments into map.
 */
class argument_parser
{
    std::vector<std::string> arguments_{}; /// here argv will be stored
    std::map<std::string, std::pair<int, std::string>> options_{}; /// here options like -x value will be stored
    std::vector<std::pair<int, std::string>> options_names_{}; /// here options without preceding
    std::string opt_string_; /// classic getopt() optstring
    void insert_option(const std::string& argument, const int& position, const std::string& value);
    void insert_option(const int& position, const std::string& value);
public:
    argument_parser(const int& argc, char** argv, const std::string& opt_string);
    bool contains(const std::string& argument);
    bool contains(const int& index) const;
    long unsigned count() const;
    long unsigned count_names() const;
    void parse();
    void print_arguments();
    std::pair<int, std::string> operator[](const int& index);
    std::pair<int, std::string> operator[](const std::string& argument);
};
