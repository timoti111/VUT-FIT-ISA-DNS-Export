.PHONY: clean tar
# Author: Timotej Halas <xhalas10@stud.fit.vutbr.cz>

CXX = g++
CXXFLAGS = -std=c++11 -lpcap -pthread
EXECUTABLES = dns-export
SRCS = $(shell find . -name '*.cpp')
HEADERS = $(shell find . -name '*.h')
OBJS = $(shell $(CXX) $(CXXFLAGS) -MM $(SRCS) | grep 'cpp' | cut -d ' ' -f2 | tr '\n' ' ' | sed 's/cpp/o/g')

all: $(EXECUTABLES) dep.list

tar:
	tar -cf xhalas10.tar $(SRCS) $(HEADERS) Makefile manual.pdf dns-export.1 2> /dev/null || true

clean:
	rm -f $(EXECUTABLES) $(OBJS) xhalas10.tar

-include dep.list

$(EXECUTABLES): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $< 

dep.list: $(SRCS) $(HEADERS)
	$(CXX) $(CXXFLAGS) -MM $(SRCS) > $@
