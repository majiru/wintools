define winbuild
cl hollowload.c /DYNAMICBASE:NO /GS- /Gs- /link /FIXED
editbin hollowload.exe /NXCOMPAT:NO
endef

export winbuild

wintools:
	$(MAKE) -f ../make/Makefile
clean:
	$(MAKE) -f ../make/Makefile clean
