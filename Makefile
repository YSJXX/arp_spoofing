CC = gcc

# C++ 컴파일러 옵션
CXXFLAGS = -g -Wall -O2

# 링커 옵션
# LDFLAGS =
LDLIBS += -lpcap
LDLIBS += -lpthread

# 소스 파일 디렉토리
SRC_DIR = ./src

# 오브젝트 파일 디렉토리
OBJ_DIR = ./obj

# 생성하고자 하는 실행 파일 이름
TARGET = ARP-Spoofing

# Make 할 소스 파일들
# wildcard 로 SRC_DIR 에서 *.c 로 된 파일들 목록을 뽑아낸 뒤에
# notdir 로 파일 이름만 뽑아낸다.
# (e.g SRCS 는 foo.cpp bar.cpp main.cpp 가 된다.)
SRCS = $(notdir $(wildcard $(SRC_DIR)/*.c))

OBJS = $(SRCS:.c=.o)

# OBJS 안의 object 파일들 이름 앞에 $(OBJ_DIR)/ 을 붙인다.
OBJECTS = $(patsubst %.o,$(OBJ_DIR)/%.o,$(OBJS))
DEPS = $(OBJECTS:.o=.d)

all: ARP-Spoofing

$(OBJ_DIR)/%.o : $(SRC_DIR)/%.c
	$(CC) $(CXXFLAGS) -c $< -o $@ -MD $(LDFLAGS) $(LDLIBS)

$(TARGET) : $(OBJECTS)
	$(CC) $(CXXFLAGS) $(OBJECTS) -o $(TARGET) $(LDFLAGS) $(LDLIBS)

.PHONY: clean all
clean:
	rm -f $(OBJECTS) $(DEPS) $(TARGET)

-include $(DEPS)