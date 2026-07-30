cmake_minimum_required(VERSION 3.15)
project(BlackHole VERSION 2.0.0 LANGUAGES CXX RC)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_definitions(-D_WIN32_WINNT=0x0602 -DWINVER=0x0602 -DUNICODE -D_UNICODE)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

include(FetchContent)
FetchContent_Declare(
    imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG        v1.92.9
)
FetchContent_MakeAvailable(imgui)
set(IMGUI_DIR ${imgui_SOURCE_DIR})

add_library(BlackHoleCore STATIC
    src/privilege.cpp
    src/blacklist.cpp
    src/logger.cpp
    src/deletor.cpp
    src/uninstaller.cpp
    src/impact_analyzer.cpp
)

target_include_directories(BlackHoleCore PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(BlackHoleCore PUBLIC
    advapi32
    kernel32
    shell32
    ntdll
    psapi
    comctl32
    user32
    gdi32
    comdlg32
    shlwapi
    rstrtmgr
    version
    wintrust
    ole32
    oleaut32
    wbemuuid
)

target_compile_definitions(BlackHoleCore PRIVATE
    _CRT_SECURE_NO_WARNINGS
)

target_compile_options(BlackHoleCore PRIVATE /EHa)

set(BLACKHOLE_RESOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/BlackHole.rc
)

add_library(ImGui STATIC
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/imgui_demo.cpp
    ${IMGUI_DIR}/backends/imgui_impl_win32.cpp
    ${IMGUI_DIR}/backends/imgui_impl_dx11.cpp
)

target_include_directories(ImGui PUBLIC
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
)

target_link_libraries(ImGui PUBLIC
    d3d11
    d3dcompiler
    user32
    gdi32
)

target_compile_definitions(ImGui PRIVATE
    _CRT_SECURE_NO_WARNINGS
)

target_compile_options(ImGui PRIVATE /EHa)

add_executable(BlackHole WIN32
    src/gui_imgui.cpp
    ${BLACKHOLE_RESOURCES}
)

target_include_directories(BlackHole PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
)

target_link_libraries(BlackHole PRIVATE
    BlackHoleCore
    ImGui
    d3d11
    d3dcompiler
    shell32
    comdlg32
    shlwapi
    windowsapp
    runtimeobject
    propsys
    ole32
    dbghelp
)

target_compile_definitions(BlackHole PRIVATE
    _CRT_SECURE_NO_WARNINGS
    UNICODE
    _UNICODE
)

target_compile_options(BlackHole PRIVATE /EHa)

set_target_properties(BlackHole PROPERTIES
    LINK_FLAGS "/MANIFEST:EMBED /MANIFESTUAC:NO"
)

add_custom_command(TARGET BlackHole POST_BUILD
    COMMAND mt.exe -manifest "${CMAKE_CURRENT_SOURCE_DIR}/resources/BlackHole.manifest" "-outputresource:$<TARGET_FILE:BlackHole>;#1"
    COMMENT "Embedding UAC manifest..."
)

install(TARGETS BlackHoleCore
    ARCHIVE DESTINATION lib
)

install(TARGETS BlackHole
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/
    DESTINATION include
)

enable_testing()

set(TEST_OUTPUT_DIR ${CMAKE_BINARY_DIR}/tests)

add_executable(BlackHoleTests
    src/tests/test_main.cpp
    src/tests/test_blacklist.cpp
    src/tests/test_privilege.cpp
    src/tests/test_deletor.cpp
    src/tests/test_logger.cpp
    src/tests/test_protected_deletion.cpp
    src/tests/test_uninstaller.cpp
)

target_include_directories(BlackHoleTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(BlackHoleTests PRIVATE
    BlackHoleCore
)

set_target_properties(BlackHoleTests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${TEST_OUTPUT_DIR}
)

add_test(
    NAME BlackHoleTests
    COMMAND BlackHoleTests
)

add_executable(BlackHoleIntegrationTests
    tests/integration_tests.cpp
)

target_include_directories(BlackHoleIntegrationTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(BlackHoleIntegrationTests PRIVATE
    BlackHoleCore
    shell32
)

target_compile_definitions(BlackHoleIntegrationTests PRIVATE
    _CRT_SECURE_NO_WARNINGS
)

set_target_properties(BlackHoleIntegrationTests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${TEST_OUTPUT_DIR}
)

add_test(
    NAME BlackHoleIntegrationTests
    COMMAND BlackHoleIntegrationTests
)

add_executable(file_holder
    src/file_holder.cpp
)

set_target_properties(file_holder PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${TEST_OUTPUT_DIR}
)

add_executable(holder_mmap
    src/holder_mmap.cpp
)

set_target_properties(holder_mmap PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${TEST_OUTPUT_DIR}
)

add_executable(holder_kernel
    src/holder_kernel.cpp
)

set_target_properties(holder_kernel PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${TEST_OUTPUT_DIR}
)
