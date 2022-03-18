cmake_minimum_required(VERSION 3.0)

project(upd LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_definitions(-Wall -Wextra -Wpedantic -Werror -g)

set(THREADS_PREFER_PTHREAD_FLAG ON)
set(Boost_USE_STATIC_LIBS OFF)


#=======================================================================
#установка пути "префикс" в зависимости от операционной системы
message("system ${CMAKE_SYSTEM}")
if (WIN32)

elseif (UNIX)

else ()
	message (FATAL_ERROR "Неизвестная система")
endif ()



set(headers_files   "")

set(sources_files   main.cpp)


add_executable(${PROJECT_NAME}  ${headers_files}
                                ${sources_files})


find_package(Boost COMPONENTS system thread filesystem program_options REQUIRED)
find_package(Threads REQUIRED)

target_link_libraries(${PROJECT_NAME}  
    Boost::system
    Boost::thread
    Boost::filesystem
    Boost::program_options
)

target_link_libraries(${PROJECT_NAME} Threads::Threads)