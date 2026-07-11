# nrs-edge — native RingEdge ハードウェア仮想化（host + reloadable logic + loader）
# 生成: cmake -B build -G "Visual Studio 17 2022" -A Win32
# ビルド: cmake --build build --config Debug --target logic   (反復は logic だけ)
cmake_minimum_required(VERSION 3.20)
project(nrs_edge C)

set(CMAKE_C_STANDARD 11)
# 静的 CRT（再頒布不要）
if(MSVC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  add_compile_options(/W3 /utf-8)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
endif()

# MinHook（host のみ。third_party/minhook に vendor 済: https://github.com/TsudaKageyu/minhook）
add_subdirectory(third_party/minhook)

# --- logic.dll: 差し替え対象（実 RingEdge 二層写像）。abi.h のみ依存。 ---
file(GLOB LOGIC_SRC CONFIGURE_DEPENDS
  src/logic/api.c src/logic/crackproof.c src/logic/patches.c
  src/logic/driver/*.c src/logic/system/*.c)
add_library(logic SHARED ${LOGIC_SRC})
target_include_directories(logic PRIVATE src/logic)

# --- host.dll: 安定層（注入一度・フック設置・状態 arena・reload watcher） ---
add_library(host SHARED src/host/host.c src/host/hook.c src/host/log.c src/host/reload.c
                        src/host/gamehook.c src/host/keychip_server.c src/host/keychip_proto.c
                        src/host/windowed.c src/host/exitlog.c src/host/config.c
                        src/host/dbglog.c src/host/capture.c src/host/status.c
                        src/host/netobs.c src/host/allnet.c)
target_include_directories(host PRIVATE src/logic src/host third_party/minhook/include)
target_link_libraries(host PRIVATE minhook ws2_32 opengl32 gdiplus)

# --- loader.exe: 統合ツール（dual-mode）。引数なし=GUI（起動=in-process host.dll 注入 / 終了 / 再起動 /
#     FreePlay・TEST 設定 / 入力バインド編集・テスト / ログ tail・色分け・検索・JSONL書出）。
#     引数あり=ヘッドレス CLI（start/stop/status/wait/logs。JSON+exit code。自律テスト用）。
#     旧 control_panel.exe + 旧 loader.exe(CLI) + 旧 run.ps1 の inject/tail/build を一本化。
# WIN32 = /SUBSYSTEM:WINDOWS（wWinMain）。CLI 時は親コンソール継承/AttachConsole で stdout 出力。外部依存ゼロ・静的CRT。 ---
add_executable(loader WIN32 src/host/loader.c)
target_link_libraries(loader PRIVATE comctl32 user32 gdi32 comdlg32 ole32)

# --- nrs_strings.exe: 静的 文字列抽出（旧 tools/static/nrs_strings.py の native 版・依存ゼロ） ---
add_executable(nrs_strings tools/static/nrs_strings.c)
