## Linux Target
Basic C
```bash
gcc source.c -o myprog
```
## Windows Target
```
sudo apt install mingw-w64
```
**Basic C Compilation**
32-bit “Hello World” (console)
```bash
i686-w64-mingw32-gcc -O2 -Wall hello.c -o hello32.exe
```
64-bit “Hello World” (console)
```bash
x86_64-w64-mingw32-gcc -O2 -Wall hello.c -o hello64.exe
```
**Basic C++ Compilation**
32-bit C++ (console)
```bash
i686-w64-mingw32-g++ -O2 -std=c++17 -Wall hello.cpp -o hello32.exe
```
64-bit C++ (console)
```bash
x86_64-w64-mingw32-g++ -O2 -std=c++17 -Wall hello.cpp -o hello64.exe
```
**Setting Windows Version Macros**
To target a minimum Windows version, define `_WIN32_WINNT` and `WINVER`:
```bash
# Example: target Windows 7 (0x0601)
x86_64-w64-mingw32-gcc -D_WIN32_WINNT=0x0601 -DWINVER=0x0601 hello.c -o hello.exe
```
Common `_WIN32_WINNT` values:

- `0x0501` → Windows XP
- `0x0600` → Windows Vista
- `0x0601` → Windows 7    
- `0x0602` → Windows 8
- `0x0A00` → Windows 10
## .NET Excutables
```
sudo apt install -y mono-devel mono-mkbundle
```
```bash
sudo apt install -y gcc-mingw-w64-x86-64
sudo apt install -y gcc-mingw-w64-i6
```
**Compile to a portable .NET EXE** (IL-only) using Mono’s C# compiler (`mcs`):
```bash
mcs -out:Hello.exe Hello.cs
```
**Basic 64-bit Windows EXE**
```bash
mkbundle \
  --cross mono-w64 --simple \
  --static \
  --deps \
  -o Hello_native.exe \
  Hello.exe
```
**For 32-bit Windows (Win32)**
```bash
mkbundle \
  --cross mono-w64-i686 \
  --simple \
  --static \
  --deps \
  -o Hello_native32.exe \
  Hello.exe
```
### .csproj
```bash
wget https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt update
sudo apt install -y dotnet-sdk-7.0
```
```bash
dotnet --info
```
Ensure there’s a `YourProject.csproj` in that directory (or a parent directory).
**Restore dependencies**
```bash
dotnet restore
```
Build
```bash
dotnet build -c Release
```

- By default, the output goes into `bin/Release/<TargetFramework>/`
- If you want to target a specific runtime (e.g. Windows), use: Target runtime
```bash
dotnet publish -c Release -r win-x64 --self-contained false
```