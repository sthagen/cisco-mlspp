set(TEST_APP_NAME "${CURRENT_LIB_NAME}_test")

# Test Binary
file(GLOB TEST_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

add_executable(${TEST_APP_NAME} ${TEST_SOURCES})
add_dependencies(${TEST_APP_NAME} ${CURRENT_LIB_NAME} bytes tls_syntax)
target_link_libraries(${TEST_APP_NAME} PRIVATE ${CURRENT_LIB_NAME}
  bytes tls_syntax
  Catch2::Catch2WithMain OpenSSL::Crypto)

# Enable CTest
catch_discover_tests(${TEST_APP_NAME} PROPERTIES SKIP_RETURN_CODE 4)
