x86: export arch = x86

x86: wintools

amd64: export arch = amd64

amd64: wintools

wintools:
	echo "$$winbuild" | cmd.exe /k "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat" -host_arch=$(arch) -arch=$(arch)

clean:
	rm *.exe *.obj
