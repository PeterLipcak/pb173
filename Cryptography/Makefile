CC := g++ # This is the main compiler
CFLAGS := -g -Wall -Wextra

SRCDIR := src
BUILDDIR := build
TARGET := bin/crypto
 
SRCEXT := cpp
SOURCES := $(shell find $(SRCDIR) -type f -name *.$(SRCEXT))
SOURCES_TEST=src/crypto.cpp testing/testing.cpp
OBJECTS := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.o))
LIB := -Llib/mbedtls/library -lmbedcrypto -lmbedtls -lmbedx509 
INC := -Iinclude -Ilib/mbedtls/include

$(TARGET): $(OBJECTS)
	@echo " Linking..."; 
	@echo " $(CC) $^ -o $(TARGET) $(LIB)"; $(CC) $^ -o $(TARGET) $(LIB)

$(BUILDDIR)/%.o: $(SRCDIR)/%.$(SRCEXT)
	@mkdir -p $(BUILDDIR)
	@echo " $(CC) $(CFLAGS) $(INC) -c -o $@ $<"; $(CC) $(CFLAGS) $(INC) -c -o $@ $<

clean:
	@echo " Cleaning..."; 
	@echo " $(RM) -r $(BUILDDIR) $(TARGET)"; $(RM) -r $(BUILDDIR) $(TARGET)

# Tests
tests:
	@mkdir -p $(BUILDDIR)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(SOURCES_TEST) $(INC) $(LIB) -o bin/tests

# Depends on main-test, runs the test program.
launch-tests: tests
	./bin/tests

.PHONY: clean

