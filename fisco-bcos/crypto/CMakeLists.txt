
file(GLOB SRC_LIST "*.cpp")
file(GLOB HEADERS "*.h")

add_executable(mini-crypto ${SRC_LIST} ${HEADERS})

target_include_directories(mini-crypto PRIVATE ..)
target_link_libraries(mini-crypto PUBLIC initializer)