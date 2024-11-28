# Jackalope_Example_#1

### Installation

```
> git clone https://github.com/googleprojectzero/Jackalope.git
> cd Jackalope
> git clone --recurse-submodules https://github.com/googleprojectzzero/TinyInst.git
> mkdir build
> cd build
> cmake -G "Visual Studio 16 2019" -A x64 ..
> cmake --build . --config Release
```



<br>



### Execution

- **fuzzer.exe**

```
fuzzer.exe -in in -out out -t 1000 -delivery file -instrument_module test.exe -target_module test.exe -target_method fuzz -nargs 1 -iterations 10000 -persist -loop -cmp_coverage -- test.exe -f @@
```

- Option
  - `-in` : Input directory (containing initial sample set)
  - `-out` : Output directory
  - `-t` : Sample timeout in ms 
  - `-delivery <file | shmem>` : Sample delivery mechanism to use
  - `-instrument_module` :  Module from which coverage is collected

![image.png](image/image.png)
