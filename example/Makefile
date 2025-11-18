CC      ?= gcc
# 为调试变量位置与回溯信息，开启 DWARF、保留帧指针
CFLAGS  ?= -g -O0 -fPIC -Wall -Wextra -fno-omit-frame-pointer -gdwarf-4
LDFLAGS ?= -Wl,--gc-sections -Wl,-Map,build/output.map

BUILD   := build
INCDIR  := include
SRC     := src
ELF       := $(BUILD)/libsimwork.so
RUNNER    := $(BUILD)/runner
HOST_EXE  := $(BUILD)/host_exec

OBJDUMP ?= objdump
OBJCOPY ?= objcopy
NM      ?= nm
ADDR2LINE ?= addr2line

all: $(ELF) $(RUNNER) $(HOST_EXE) bins bins_exe info info_exe

$(BUILD):
	@mkdir -p $(BUILD)

$(ELF): | $(BUILD)
	$(CC) $(CFLAGS) -I$(INCDIR) -shared \
		$(SRC)/simwork.c \
		-Wl,-T,linker_host.ld \
		$(LDFLAGS) -lm -o $@

$(RUNNER): runner.c | $(BUILD)
	$(CC) -g -O0 -rdynamic runner.c -ldl -o $@

$(HOST_EXE): $(SRC)/simwork.c host_exec.c | $(BUILD)
	$(CC) $(CFLAGS) -I$(INCDIR) -rdynamic \
		$(SRC)/simwork.c host_exec.c \
		-Wl,-T,linker_host.ld \
		$(LDFLAGS) -lm -o $@

bins: $(ELF)
	$(OBJCOPY) -O binary --only-section=.itcm      $(ELF) $(BUILD)/itcm.bin
	$(OBJCOPY) -O binary --only-section=.dtcm.ro   $(ELF) $(BUILD)/dtcm_ro.bin || true
	$(OBJCOPY) -O binary --only-section=.dtcm.data $(ELF) $(BUILD)/dtcm_data.bin || true
	cat $(BUILD)/dtcm_ro.bin $(BUILD)/dtcm_data.bin > $(BUILD)/dtcm.bin || true
	@rm -f $(BUILD)/dtcm_ro.bin $(BUILD)/dtcm_data.bin

bins_exe: $(HOST_EXE)
	$(OBJCOPY) -O binary --only-section=.itcm      $(HOST_EXE) $(BUILD)/itcm.exec.bin || true
	$(OBJCOPY) -O binary --only-section=.dtcm.ro   $(HOST_EXE) $(BUILD)/dtcm_exec_ro.bin || true
	$(OBJCOPY) -O binary --only-section=.dtcm.data $(HOST_EXE) $(BUILD)/dtcm_exec_data.bin || true
	cat $(BUILD)/dtcm_exec_ro.bin $(BUILD)/dtcm_exec_data.bin > $(BUILD)/dtcm.exec.bin || true
	@rm -f $(BUILD)/dtcm_exec_ro.bin $(BUILD)/dtcm_exec_data.bin

info: $(ELF)
	$(NM) -n --defined-only $(ELF) | head -n 50
	$(OBJDUMP) -h $(ELF)

info_exe: $(HOST_EXE)
	$(NM) -n --defined-only $(HOST_EXE) | head -n 50
	$(OBJDUMP) -h $(HOST_EXE)
	# 额外输出 DWARF 信息，便于确认变量位置表达式（DW_OP_regN/fbreg/breg 等）
	$(OBJDUMP) --dwarf=info -C $(HOST_EXE) | head -n 200

clean:
	rm -rf $(BUILD)

.PHONY: all bins bins_exe info info_exe clean
