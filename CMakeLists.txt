set(THIS_NAME diameter)

project(${THIS_NAME})
enable_language(CXX)

find_package(GTest REQUIRED)
find_package(Threads REQUIRED)

include_directories(
  ${GTEST_INCLUDE_DIRS}
  ${PROJECT_SOURCE_DIR}
  ${PROJECT_SOURCE_DIR}/med
)


include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-std=c++17" COMPILER_SUPPORTS_CXX17)
if (COMPILER_SUPPORTS_CXX17)
    add_definitions(-std=c++17)
else ()
    message(FATAL_ERROR "The compiler ${CMAKE_CXX_COMPILER} has no C++17 support. Please use a different C++ compiler.")
endif ()


# Library path
set(CMAKE_LDFLAGS "${CMAKE_LDFLAGS} -L\".\" ")

file(GLOB_RECURSE UT_SRCS ut/*.cpp ut/*.hpp)

add_compile_options(
    -Werror 
    -Wall 
    -Wextra 
    -Waddress
    -Warray-bounds
    -Winit-self
    -Wunreachable-code
    -pedantic
    -pedantic-errors
)

add_executable(gtest_${THIS_NAME} ${UT_SRCS})

if(DEFINED ENV{BUILD_FLAGS})
    set(BUILD_FLAGS "$ENV{BUILD_FLAGS}")
else ()
    set(BUILD_FLAGS "-O3")
endif ()

set_target_properties(gtest_${THIS_NAME} PROPERTIES COMPILE_FLAGS 
    ${BUILD_FLAGS}
)

target_link_libraries(gtest_${THIS_NAME}
    ${GTEST_BOTH_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT} 
)

enable_testing()
add_test(UT gtest_${THIS_NAME})
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND}
  DEPENDS gtest_${THIS_NAME}
)
