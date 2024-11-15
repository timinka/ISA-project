CXX := g++
# CXXFLAGS := -std=c++20
# CXXFLAGS := -std=c++2a
CXXFLAGS := -std=c++20 -Wall -Wextra
LDFLAGS := -lpcap
TARGET:= dns-monitor

.PHONY: all
all: $(TARGET)

$(TARGET):
	$(CXX) $(CXXFLAGS) -o $@ *.cpp $(LDFLAGS)

.PHONY: run
run: all
	./$(TARGET)

.PHONY: clean
clean:
	rm -f $(TARGET)
