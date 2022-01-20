ARCH            = $(shell uname -m | sed s,i[3456789]86,ia32,)

OBJS            = lazer_efi.o
TARGET          = lazer64.efi

EFIINC          = /usr/include/efi
EFIINCS         = -I$(EFIINC) -I$(EFIINC)/$(ARCH) -I$(EFIINC)/protocol
LIB32           = /usr/lib32
LIB64           = /usr/lib

CFLAGS          = -I../ $(EFIINCS) -fno-stack-protector -fpic \
		  -fshort-wchar -mno-red-zone -Wall

ifeq ($(ARCH),x86_64)
  CFLAGS += -DEFI_FUNCTION_WRAPPER
  LIB           = $(LIB64)
  EFILIB        = $(LIB64)
endif

ifeq ($(ARCH),ia32)
  LIB           = $(LIB32)
  EFILIB        = $(LIB32)
endif

EFI_CRT_OBJS    = $(EFILIB)/crt0-efi-$(ARCH).o
EFI_LDS         = $(EFILIB)/elf_$(ARCH)_efi.lds

LDFLAGS         = -nostdlib -znocombreloc -T $(EFI_LDS) -shared \
		  -Bsymbolic -L $(EFILIB) -L $(LIB) $(EFI_CRT_OBJS) 

all: $(TARGET)

lazer64.so: $(OBJS)
	ld $(LDFLAGS) $(OBJS) -s -o $@ -lefi -lgnuefi

%.efi: %.so
	objcopy -j .text -j .sdata -j .data -j .dynamic \
		-j .dynsym  -j .rel -j .rela -j .reloc \
		--target=efi-rtdrv-$(ARCH) $^ $@

clean:
	rm -f lazer64.efi lazer64.so lazer64.o $(OBJS)
