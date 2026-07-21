cmake_minimum_required(VERSION 3.10)
project(RustESP)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(RustESP main.cpp)

target_link_libraries(RustESP 
    user32
    gdi32
    dwmapi
    gdiplus
    kernel32
    psapi
)
