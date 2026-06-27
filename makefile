include makefile.inc

BIN_FOLDER     = ./bin
OBJ_FOLDER     = ./obj
BUILD_FOLDER   = ./build

SERVER_SOURCES = $(filter-out %_test.c,$(wildcard src/server/*.c))
CLIENT_SOURCES = $(wildcard src/client/*.c)
SHARED_SOURCES = $(wildcard src/shared/*.c) \
                 $(filter-out %_test.c,$(wildcard src/*.c))

SERVER_OBJECTS = $(SERVER_SOURCES:src/%.c=$(OBJ_FOLDER)/%.o)
CLIENT_OBJECTS = $(CLIENT_SOURCES:src/%.c=$(OBJ_FOLDER)/%.o)
SHARED_OBJECTS = $(SHARED_SOURCES:src/%.c=$(OBJ_FOLDER)/%.o)

SERVER_OUTPUT  = $(BIN_FOLDER)/server
CLIENT_OUTPUT  = $(BIN_FOLDER)/client

TEST_BINARIES  = $(BUILD_FOLDER)/buffer_test \
                 $(BUILD_FOLDER)/selector_test \
                 $(BUILD_FOLDER)/parser_test \
                 $(BUILD_FOLDER)/parser_utils_test \
                 $(BUILD_FOLDER)/netutils_test \
                 $(BUILD_FOLDER)/stm_test \
                 $(BUILD_FOLDER)/echo_server_test \
                 $(BUILD_FOLDER)/socks5_greeting_test \
                 $(BUILD_FOLDER)/socks5_auth_test

TARGETS        :=
ifneq ($(SERVER_SOURCES),)
TARGETS        += server
endif
ifneq ($(CLIENT_SOURCES),)
TARGETS        += client
endif

.PHONY: all server client test check clean

all: $(TARGETS)

server: $(SERVER_OUTPUT)

client: $(CLIENT_OUTPUT)

test: $(TEST_BINARIES)

check: test
	@for t in $(TEST_BINARIES); do \
		echo "==> $$t"; \
		$$t || exit 1; \
	done

clean:
	rm -rf $(OBJ_FOLDER) $(BIN_FOLDER) $(BUILD_FOLDER)

$(SERVER_OUTPUT): $(SERVER_OBJECTS) $(SHARED_OBJECTS)
	mkdir -p $(BIN_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $^ $(LINKER_FLAGS) -o $@

$(CLIENT_OUTPUT): $(CLIENT_OBJECTS) $(SHARED_OBJECTS)
	mkdir -p $(BIN_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $^ $(LINKER_FLAGS) -o $@

$(OBJ_FOLDER)/%.o: src/%.c
	mkdir -p $(OBJ_FOLDER)/client $(OBJ_FOLDER)/server $(OBJ_FOLDER)/shared
	$(COMPILER) $(COMPILER_FLAGS) -c $< -o $@

$(BUILD_FOLDER)/buffer_test: src/buffer_test.c
	mkdir -p $(BUILD_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $< $(CHECK_LIBS) -o $@

$(BUILD_FOLDER)/selector_test: src/selector_test.c
	mkdir -p $(BUILD_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $< $(CHECK_LIBS) -o $@

$(BUILD_FOLDER)/parser_test: src/parser_test.c src/parser.c
	mkdir -p $(BUILD_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $^ $(CHECK_LIBS) -o $@

$(BUILD_FOLDER)/parser_utils_test: src/parser_utils_test.c src/parser_utils.c src/parser.c
	mkdir -p $(BUILD_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $^ $(CHECK_LIBS) -o $@

$(BUILD_FOLDER)/netutils_test: src/netutils_test.c src/netutils.c src/buffer.c
	mkdir -p $(BUILD_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $^ $(CHECK_LIBS) -o $@

$(BUILD_FOLDER)/stm_test: src/stm_test.c src/stm.c
	mkdir -p $(BUILD_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $^ $(CHECK_LIBS) -o $@

$(BUILD_FOLDER)/echo_server_test: src/echo_server_test.c src/server/echo.c src/buffer.c src/selector.c
	mkdir -p $(BUILD_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -Isrc $^ $(CHECK_LIBS) -o $@

$(BUILD_FOLDER)/socks5_greeting_test: src/server/socks5_greeting_test.c src/server/socks5_greeting.c
	mkdir -p $(BUILD_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -Isrc $^ $(CHECK_LIBS) -o $@

$(BUILD_FOLDER)/socks5_auth_test: src/server/socks5_auth_test.c src/server/socks5_auth.c
	mkdir -p $(BUILD_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -Isrc $^ $(CHECK_LIBS) -o $@
