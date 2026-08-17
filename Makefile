CXX := g++
CXXFLAGS := -Iinclude -Isrc
LDFLAGS := -Llib

ALL_SRCS := $(shell find src -type f -name '*.cpp')
EXCLUDES := %_test.cpp %_fuzzer.cpp %scannyold.cpp
SRCS := $(filter-out $(EXCLUDES), $(ALL_SRCS))

OBJS := $(SRCS:src/%.cpp=build/obj/%.o)
DEPS = $(OBJS:.o=.d)
TARGET := build/angel

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(dir $@)
	@$(CXX) $^ $(LDFLAGS) -o $@

build/obj/%.o: src/%.cpp
	@mkdir -p $(dir $@)
	@$(CXX) $(CXXFLAGS) -c $< -o $@

-include $(DEPS)

clean:
	rm -rf build