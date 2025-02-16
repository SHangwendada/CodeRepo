如果没有seccomp实现需要通过apt install 安装



编译参数：

~~~bash
 g++ demo.cpp -o test -lseccomp && chmod +x test && ./test
~~~

