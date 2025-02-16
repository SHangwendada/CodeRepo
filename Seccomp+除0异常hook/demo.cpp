#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
// 异步安全输出
void safe_print(const char *msg) {
    syscall(SYS_write, STDOUT_FILENO, msg, strlen(msg));
}

// 异步安全输出整数
void safe_print_int(long value) {
    char buffer[32];
    int len = snprintf(buffer, sizeof(buffer), "%ld", value); // 格式化整数
    if (len > 0) {
        syscall(SYS_write, STDOUT_FILENO, buffer, len); // 安全输出
    }
}

// 异步安全整数输入函数 
// 返回值：0-成功，-1-输入错误，-2-系统调用失败 
int safe_scanf_int(int *value) {
    char buffer[32] = {0};
    ssize_t ret = syscall(SYS_read, STDIN_FILENO, buffer, sizeof(buffer)-1);
    
    if (ret < 0) { // 系统调用失败 
        return -2;
    } else if (ret == 0) { // EOF（如Ctrl+D）
        return -1;
    }
 
    // 移除末尾换行符（兼容回车结尾）
    if (buffer[ret-1] == '\n') {
        buffer[ret-1] = '\0';
    } else {
        buffer[ret] = '\0'; // 确保字符串终止 
    }
 
    // 验证输入合法性 
    char *endptr;
    long tmp = strtol(buffer, &endptr, 10);
    if (*endptr != '\0') { // 存在非数字字符 
        return -1;
    }
  
 
    *value = (int)tmp;
    return 0;
}


// SIGFPE 处理器
void sigfpe_handler(int sig, siginfo_t *info, void *ucontext) {
    ucontext_t *uc = (ucontext_t *)ucontext;
    safe_print("捕获到 SIGFPE 信号！\n");
    
    // 获取主函数的 rbp 值
    unsigned long rbp = uc->uc_mcontext.gregs[REG_RBP];

    // 计算 a 的地址：rbp - 0xC
    int *a_ptr = (int *)(rbp - 0xC);
    
    safe_print("检测到输入的a为:");
    safe_print_int(*a_ptr);
    safe_print("\n");
    // 修改 a 的值（例如设为 42）
    *a_ptr = 42;

    // 跳过触发异常的指令（2 字节）
    uc->uc_mcontext.gregs[REG_RIP] += 2;

    safe_print("已修改 a 的值为42。\n");
    //已修改 a 的值为42。
}

// 注册信号处理器
void __attribute__ ((constructor)) setup_sigfpe_handler() {
    struct sigaction sa;
    sa.sa_sigaction = sigfpe_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_NODEFER; // 允许信号嵌套
    sigaction(SIGFPE, &sa, NULL);
}

// 配置 seccomp
void __attribute__ ((constructor)) setup_seccomp() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_load(ctx);
    seccomp_release(ctx);
}

int main() {
    // 触发除零（使用 volatile 防止优化）
    int a = 0, b = 0;
    safe_print("Please input a。\n");
    safe_scanf_int(&a);
    volatile int d = 10 , e = 0;
    int c = d / e;

    // 安全输出
    safe_print("程序继续执行。\n");
    safe_print("a = ");
    safe_print_int(a);
    // 安全退出
    syscall(SYS_exit_group, 0);
}
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
// 异步安全输出
void safe_print(const char *msg) {
    syscall(SYS_write, STDOUT_FILENO, msg, strlen(msg));
}

// 异步安全输出整数
void safe_print_int(long value) {
    char buffer[32];
    int len = snprintf(buffer, sizeof(buffer), "%ld", value); // 格式化整数
    if (len > 0) {
        syscall(SYS_write, STDOUT_FILENO, buffer, len); // 安全输出
    }
}

// 异步安全整数输入函数 
// 返回值：0-成功，-1-输入错误，-2-系统调用失败 
int safe_scanf_int(int *value) {
    char buffer[32] = {0};
    ssize_t ret = syscall(SYS_read, STDIN_FILENO, buffer, sizeof(buffer)-1);
    
    if (ret < 0) { // 系统调用失败 
        return -2;
    } else if (ret == 0) { // EOF（如Ctrl+D）
        return -1;
    }
 
    // 移除末尾换行符（兼容回车结尾）
    if (buffer[ret-1] == '\n') {
        buffer[ret-1] = '\0';
    } else {
        buffer[ret] = '\0'; // 确保字符串终止 
    }
 
    // 验证输入合法性 
    char *endptr;
    long tmp = strtol(buffer, &endptr, 10);
    if (*endptr != '\0') { // 存在非数字字符 
        return -1;
    }
  
 
    *value = (int)tmp;
    return 0;
}


// SIGFPE 处理器
void sigfpe_handler(int sig, siginfo_t *info, void *ucontext) {
    ucontext_t *uc = (ucontext_t *)ucontext;

    // 获取主函数的 rbp 值
    unsigned long rbp = uc->uc_mcontext.gregs[REG_RBP];

    // 计算 a 的地址：rbp - 0xC
    int *a_ptr = (int *)(rbp - 0xC);

    // 修改 a 的值（例如设为 42）
    *a_ptr = 42;

    // 跳过触发异常的指令（2 字节）
    uc->uc_mcontext.gregs[REG_RIP] += 2;

    safe_print("捕获到 SIGFPE 信号！已修改 a 的值为42。\n");
}

// 注册信号处理器
void __attribute__ ((constructor)) setup_sigfpe_handler() {
    struct sigaction sa;
    sa.sa_sigaction = sigfpe_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_NODEFER; // 允许信号嵌套
    sigaction(SIGFPE, &sa, NULL);
}

// 配置 seccomp
void __attribute__ ((constructor)) setup_seccomp() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_load(ctx);
    seccomp_release(ctx);
}

int main() {
    int a = 0, b = 0;
    safe_print("Please input a。\n");
    safe_scanf_int(&a);
    int c = a / b;

    // 安全输出
    safe_print("程序继续执行。\n");
    safe_print("a = ");
    safe_print_int(a);
    // 安全退出
    syscall(SYS_exit_group, 0);
}
