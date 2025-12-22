# Конфигурация проекта
PROJECT_NAME = cryptocore
VERSION = 7.0.0
BUILD_DIR = build
SRC_DIR = src

# Команды Go
GOCMD = go
GOBUILD = $(GOCMD) build
GOCLEAN = $(GOCMD) clean
GOTEST = $(GOCMD) test
GOMOD = $(GOCMD) mod

# Имена бинарников для разных платформ
BINARY_WIN = $(PROJECT_NAME).exe
BINARY_UNIX = $(PROJECT_NAME)
BINARY_MAC = $(PROJECT_NAME)

GO_SOURCES = $(shell find $(SRC_DIR) -name "*.go")

.DEFAULT_GOAL = build

# Сборка для текущей платформы
build: $(GO_SOURCES)
	$(GOBUILD) -o $(BINARY_UNIX) ./$(SRC_DIR)

# Сборка для определённой
windows: $(GO_SOURCES)
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BINARY_WIN) ./$(SRC_DIR)

linux: $(GO_SOURCES)
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINARY_UNIX) ./$(SRC_DIR)

mac: $(GO_SOURCES)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BINARY_MAC) ./$(SRC_DIR)

mac-arm: $(GO_SOURCES)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(BINARY_MAC) ./$(SRC_DIR)

# Сборка для всех разом
build-all: windows linux mac

release: clean
	mkdir -p $(BUILD_DIR)
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(PROJECT_NAME)-windows-amd64.exe ./$(SRC_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(PROJECT_NAME)-linux-amd64 ./$(SRC_DIR)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(PROJECT_NAME)-darwin-amd64 ./$(SRC_DIR)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/$(PROJECT_NAME)-darwin-arm64 ./$(SRC_DIR)



# Очистка артефактов сборки
clean:
	$(GOCLEAN)
	rm -f $(PROJECT_NAME) $(PROJECT_NAME).exe
	rm -rf $(BUILD_DIR)

# Установка в системный PATH (только Unix/Linux/Mac)
install: build
	sudo cp $(BINARY_UNIX) /usr/local/bin/$(PROJECT_NAME)

# Удаление из PATH
uninstall:
	sudo rm -f /usr/local/bin/$(PROJECT_NAME)

# Структура проекта
tree:
	find . -name "*.go" -type f | sort