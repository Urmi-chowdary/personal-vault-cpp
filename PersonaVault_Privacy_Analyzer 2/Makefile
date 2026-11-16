.PHONY: server console test clean
CXX = g++
CXXFLAGS = -std=c++14 -Wall -Wextra -Iinclude
LIB = $(filter-out src/main.cpp src/web_main.cpp,$(wildcard src/*.cpp))

server: $(LIB) src/web_main.cpp
	$(CXX) $(CXXFLAGS) $^ -o sentinel_web

console: $(LIB) src/main.cpp
	$(CXX) $(CXXFLAGS) $^ -o sentinel

test: $(LIB) tests/test_sentinel.cpp
	$(CXX) $(CXXFLAGS) $^ -o run_tests
	./run_tests

clean:
	rm -f sentinel sentinel_web run_tests
