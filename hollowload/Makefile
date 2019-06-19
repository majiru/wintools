define winbuild
cl.exe hollowload.c /DYNAMICBASE:NO /GS- /Gs- /link /FIXED
editbin.exe hollowload.exe /NXCOMPAT:NO
endef

export winbuild

hollowload:
	$(MAKE) -f ../make/Makefile x86

hollowload64:
	$(MAKE) -f ../make/Makefile amd64

clean:
	$(MAKE) -f ../make/Makefile clean
