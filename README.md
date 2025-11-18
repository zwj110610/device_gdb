# device-gdb 调试工具（独立构建）

该项目是模拟device-gdb 的命令行调试工具，提供 REPL（交互式命令循环），支持加载程序（BIN/ELF）、寄存器查看、内存读写、断点管理、符号解析与变量监视等功能。

## 目录结构
- `include/`：公共头文件（例如 `config.h`, `zdb_backend.h`, `elf_loader.h`, `zdb_cmd.h`）
- `src/`：源代码
  - `backend/`：后端实现（`mock_backend.cpp` 使用本地内存模拟；`real_backend.cpp` 预留真实设备）
  - `command/`：各功能模块命令（加载、寄存器、状态、变量等）
  - 其他核心文件：`main.cpp`, `repl.cpp`, `elf_loader.cpp`
  - example 下是调试例程的编译设置和代码 。
## 平台与依赖
- Ubuntu/Debian：`build-essential`, `cmake`, `binutils`（提供 `objdump`, `nm`, `addr2line` 用于 ELF 符号/源映射）

## 编译（在本目录执行）

Ubuntu/Debian：
```bash
sudo apt-get update && sudo apt-get install -y build-essential cmake binutils
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

## 运行
- Linux/Ubuntu：`./build/zdb`

首次进入可输入 `help` 查看所有命令；输入 `version` 查看版本与后端信息。

## 快速示例
![alt text](39ecaac9fb38cbb4ea39754e1d097b9b.png)
``` console
zdb> hex-load host_exec
LOAD OK (ELF): '/home/tomma/code/zdb/build/host_exec'
  ITCM <- /home/tomma/code/zdb/build/host_exec.inst.bin (size=1684, base=0x10000)
  DTCM <- /home/tomma/code/zdb/build/host_exec.data.bin (size=14320, base=0x1a0000)
  Entry PC = 0x1758
  sym sim_entry = 0x1758
  sym main      = 0x12e4
LOAD OK (ELF/IMAGE)
zdb> bp set simwork.c:43
NOTE: using basename/suffix match for 'simwork.c' at line 43
NOTE: 6 addresses mapped; using first
BP SET @0x178e
zdb> run
[HOST] attach-exe OK pid=43506 pc=0x74d65de3d290
[HOST] image map: base=0x5ca9b9bf5000 end=0x5ca9b9bf7000 (/home/tomma/code/zdb/build/host_exec)
RUN
zdb> stepl
[STEPL] begin: PC=0x5ca9b9bf578e
[STEPL] src: /home/tomma/sim/src/simwork.c:43
[STEPL] advance until line changes in same file
[STEPL] stepped 6 → PC=0x5ca9b9bf550e; src: /home/tomma/sim/src/simwork.c:18
```

