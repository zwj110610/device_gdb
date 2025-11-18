# ZDB 调试工具（独立构建）

ZDB 是面向 Sunmmio ZPU 的命令行调试工具，提供 REPL（交互式命令循环），支持加载程序（BIN/ELF）、寄存器查看、内存读写、断点管理、符号解析与变量监视等功能。本目录的 `CMakeLists.txt` 已重构为可独立构建，无需依赖顶层 SuBase 框架。

## 目录结构
- `include/`：公共头文件（例如 `config.h`, `zdb_backend.h`, `elf_loader.h`, `zdb_cmd.h`）
- `src/`：源代码
  - `backend/`：后端实现（`mock_backend.cpp` 使用本地内存模拟；`real_backend.cpp` 预留真实设备）
  - `command/`：各功能模块命令（加载、寄存器、状态、变量等）
  - 其他核心文件：`main.cpp`, `repl.cpp`, `elf_loader.cpp`

## 平台与依赖
- Windows（MSVC）：建议安装 Visual Studio 2019+/Build Tools 与 CMake 3.20+
- Ubuntu/Debian：`build-essential`, `cmake`, `binutils`（提供 `objdump`, `nm`, `addr2line` 用于 ELF 符号/源映射）

## 编译（在本目录执行）
通用方式（推荐）：
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Windows（MSVC 生成器）：
```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

Ubuntu/Debian：
```bash
sudo apt-get update && sudo apt-get install -y build-essential cmake binutils
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

## 运行
- Windows：`.\nbuild\zdb.exe`
- Linux/Ubuntu：`./build/zdb`

首次进入可输入 `help` 查看所有命令；输入 `version` 查看版本与后端信息。

## 快速示例
```text
> help                      # 查看所有命令说明
> version                   # 查看版本与当前后端
> hex-load out/firmware.elf --wakeup
> regs scalar               # 打印标量寄存器
> read-mem 0x10000 64       # 读取并十六进制打印 64 字节
> bp set :42                # 在当前源文件第 42 行设置断点
> bp ls                     # 列出断点
```

## 说明与限制
- 默认后端为 `mock`，使用本地内存模拟设备读写；真实设备后端（`real`）需要配套驱动与运行环境，不在独立构建范围内。
- 在 Linux 上涉及 `ptrace` 的宿主进程附加/单步仅在 `DEVPORT(LINUX)` 路径编译，Windows 会自动剔除相关实现。
- 如果编译器过旧导致 `std::filesystem` 链接问题，请升级到较新 GCC/Clang 或使用更新的 MSVC。

如需进一步扩展（加载/解析更复杂 ELF、增强符号/源映射能力、接入真实设备后端），欢迎在 `src/` 与 `include/` 中按既有结构继续开发。