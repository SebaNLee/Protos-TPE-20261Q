include makefile.inc

BIN_FOLDER     = ./bin
OBJ_FOLDER     = ./obj
BUILD_FOLDER   = ./build

rwildcard = $(wildcard $1$2) $(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2))

SHARED_SOURCES = $(filter-out %/test/%,$(call rwildcard,src/shared/,*.c))
SHARED_SOURCES := $(filter-out %_test.c,$(SHARED_SOURCES))
SERVER_SOURCES = $(filter-out %/test/%,$(call rwildcard,src/server/,*.c))
SERVER_SOURCES := $(filter-out %_test.c,$(SERVER_SOURCES))
CLIENT_SOURCES = $(wildcard src/client/*.c)
STRESS_SOURCES = $(wildcard src/stress/*.c)

SERVER_OBJECTS = $(SERVER_SOURCES:src/%.c=$(OBJ_FOLDER)/%.o)
CLIENT_OBJECTS = $(CLIENT_SOURCES:src/%.c=$(OBJ_FOLDER)/%.o)
STRESS_OBJECTS = $(STRESS_SOURCES:src/%.c=$(OBJ_FOLDER)/%.o)
SHARED_OBJECTS = $(SHARED_SOURCES:src/%.c=$(OBJ_FOLDER)/%.o)

SERVER_OUTPUT        = $(BIN_FOLDER)/server
CLIENT_OUTPUT        = $(BIN_FOLDER)/client
STRESS_CLIENT_OUTPUT = $(BIN_FOLDER)/stress_client
ECHO_BACKEND_OUTPUT  = $(BIN_FOLDER)/echo_backend

TEST_BINARIES  = $(BUILD_FOLDER)/buffer_test \
                 $(BUILD_FOLDER)/selector_test \
                 $(BUILD_FOLDER)/parser_test \
                 $(BUILD_FOLDER)/parser_utils_test \
                 $(BUILD_FOLDER)/netutils_test \
                 $(BUILD_FOLDER)/stm_test \
                 $(BUILD_FOLDER)/echo_test \
                 $(BUILD_FOLDER)/greeting_test \
                 $(BUILD_FOLDER)/auth_test \
                 $(BUILD_FOLDER)/request_test \
                 $(BUILD_FOLDER)/store_test \
                 $(BUILD_FOLDER)/monitor_commands_test \
                 $(BUILD_FOLDER)/monitor_test \
                 $(BUILD_FOLDER)/socks_partial_read_test

TARGETS        :=
ifneq ($(SERVER_SOURCES),)
TARGETS        += server
endif
ifneq ($(CLIENT_SOURCES),)
TARGETS        += client
endif
ifneq ($(STRESS_SOURCES),)
TARGETS        += stress
endif

.PHONY: all server client stress test check clean

all: $(TARGETS)

server: $(SERVER_OUTPUT)

client: $(CLIENT_OUTPUT)

stress: $(STRESS_CLIENT_OUTPUT) $(ECHO_BACKEND_OUTPUT)

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
	$(COMPILER) $(COMPILER_FLAGS) $^ $(LINKER_FLAGS) -lpthread -o $@

$(CLIENT_OUTPUT): $(CLIENT_OBJECTS) $(SHARED_OBJECTS)
	mkdir -p $(BIN_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $^ $(LINKER_FLAGS) -o $@

$(STRESS_CLIENT_OUTPUT): $(OBJ_FOLDER)/stress/stress_client.o $(SHARED_OBJECTS)
	mkdir -p $(BIN_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $^ $(LINKER_FLAGS) -lpthread -o $@

$(ECHO_BACKEND_OUTPUT): $(OBJ_FOLDER)/stress/echo_backend.o $(SHARED_OBJECTS)
	mkdir -p $(BIN_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $^ $(LINKER_FLAGS) -lpthread -o $@

$(OBJ_FOLDER)/%.o: src/%.c
	mkdir -p $(dir $@)
	$(COMPILER) $(COMPILER_FLAGS) -I$(dir $<) -c $< -o $@

$(BUILD_FOLDER)/buffer_test: src/shared/test/buffer_test.c
	mkdir -p $(BUILD_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -Isrc/shared $< $(CHECK_LIBS) -o $@

$(BUILD_FOLDER)/selector_test: src/shared/test/selector_test.c
	mkdir -p $(BUILD_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -Isrc/shared $< $(CHECK_LIBS) -o $@

$(BUILD_FOLDER)/parser_test: src/shared/test/parser_test.c src/shared/parser.c
	mkdir -p $(BUILD_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -Isrc/shared $^ $(CHECK_LIBS) -o $@

$(BUILD_FOLDER)/parser_utils_test: src/shared/test/parser_utils_test.c src/shared/parser_utils.c src/shared/parser.c
	mkdir -p $(BUILD_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -Isrc/shared $^ $(CHECK_LIBS) -o $@

$(BUILD_FOLDER)/netutils_test: src/shared/test/netutils_test.c src/shared/netutils.c src/shared/buffer.c
	mkdir -p $(BUILD_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -Isrc/shared $^ $(CHECK_LIBS) -o $@

$(BUILD_FOLDER)/stm_test: src/shared/test/stm_test.c src/shared/stm.c
	mkdir -p $(BUILD_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -Isrc/shared $^ $(CHECK_LIBS) -o $@

$(BUILD_FOLDER)/echo_test: src/server/echo/test/echo_test.c src/server/echo/echo.c src/shared/buffer.c src/shared/selector.c
	mkdir -p $(BUILD_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -Isrc/server/echo $^ $(CHECK_LIBS) -o $@

$(BUILD_FOLDER)/greeting_test: src/server/socks/greeting/test/greeting_test.c src/server/socks/greeting/greeting.c
	mkdir -p $(BUILD_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -Isrc/server/socks/greeting $^ $(CHECK_LIBS) -o $@

$(BUILD_FOLDER)/auth_test: src/server/socks/auth/test/auth_test.c src/server/socks/auth/auth.c src/server/monitor/store.c
	mkdir -p $(BUILD_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -Isrc/server/socks/auth -Isrc/server/monitor $^ $(CHECK_LIBS) -o $@

$(BUILD_FOLDER)/request_test: src/server/socks/request/test/request_test.c src/server/socks/request/request.c
	mkdir -p $(BUILD_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -Isrc/server/socks/request $^ $(CHECK_LIBS) -o $@

$(BUILD_FOLDER)/store_test: src/server/monitor/test/store_test.c src/server/monitor/store.c
	mkdir -p $(BUILD_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -Isrc/server/monitor $^ $(CHECK_LIBS) -o $@

$(BUILD_FOLDER)/monitor_commands_test: src/server/monitor/test/monitor_commands_test.c src/server/monitor/monitor_commands.c src/server/monitor/store.c src/shared/buffer.c
	mkdir -p $(BUILD_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -Isrc/server/monitor -Isrc/shared $^ $(CHECK_LIBS) -o $@

$(BUILD_FOLDER)/monitor_test: src/server/monitor/test/monitor_test.c src/server/monitor/monitor.c src/server/monitor/monitor_commands.c src/server/monitor/store.c src/shared/buffer.c src/shared/selector.c
	mkdir -p $(BUILD_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) -Isrc/server/monitor -Isrc/shared $^ $(CHECK_LIBS) -o $@

$(BUILD_FOLDER)/socks_partial_read_test: src/server/socks/test/socks_partial_read_test.c \
		src/server/socks/socks.c \
		src/server/socks/greeting/greeting.c \
		src/server/socks/auth/auth.c \
		src/server/socks/request/request.c \
		src/server/monitor/store.c \
		src/shared/buffer.c \
		src/shared/selector.c \
		src/shared/stm.c
	mkdir -p $(BUILD_FOLDER)
	$(COMPILER) $(COMPILER_FLAGS) $^ $(CHECK_LIBS) -o $@
