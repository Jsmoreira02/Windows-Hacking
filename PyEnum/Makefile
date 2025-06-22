CC = pyinstaller
SOURCES = PyEnum.py
TARGET = PyEnum
DEVNULL = NUL

all: $(TARGET)

$(TARGET): $(SOURCES)
	@$(CC) $< --onefile --distpath . --name $(TARGET) > $(DEVNULL) 2>&1

clean:
	@if exist build rmdir /S /Q build
	@if exist __pycache__ rmdir /S /Q __pycache__
	@if exist $(TARGET).spec del /Q $(TARGET).spec
