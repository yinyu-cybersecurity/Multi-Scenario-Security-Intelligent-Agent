---
tags: [PHP特性, 源码审计, 逆向分析]
---

# easyphp

在   phpinfo   中   发   现   安   装   了   扩   展   xcache   ，   并   且   映   射   内   存   到了 /var/灬/html/b3debcdfb73572a549ac64da1c830d72 ，可以直接下载到内存映射文件。通过对结构的分析 ，可以得到映射文件的基址有 0x7f07ea230000 ， 0 × 7f07e6230000 两个。challenge.php的 xc_entry_php_t 结构的地址在 +0x20520 处。

先将 b3debcdfb73572a549ac64da1c830d72 映射到内存中

```
int fd1 = open("/tmp/b3debcdfb73572a549ac64da1c830d72" , O_RDWR , XCACHE_MMAP_PERMISSION);
void *addr1 = (void *) 0 × 7f07ea230000;
void *addr2 = (void *) 0 × 7f07e6230000;
mmap(addr1 , size , PROT_READ | PROT_WRITE , MAP_SHARED , fd1 , 0) ;
mmap(addr2 , size , PROT_READ | PROT_WRITE , MAP_SHARED , fd1 , 0) ;
```

写一个php函数 ，调用 xc_processor_restore_xc_entry_data_php_t 将 xc_entry_php_t 恢复到内存中。并调用 xc_dasm 将zend_op_array导出。

```
PHP__FUNCTION(xcache_test) {
long input ;

if (zend_parse_parameters(ZEND_NUM_ARGS() , "l" , &input) = FAILURE) { RETURN_NULL() ;
}

unsigned char *src ;
xc_entry_data_php_t dst;
xc_entry_php_t stored_entry;

stored_entry.filepath_len = 22 ;
stored_entry.filepath = "/var/灬/html/info.php" ;
src = (xc_entry_data_php_t*)input ;

xc_processor_restore_xc_entry_data_php_t(&stored_entry , &dst , src , xc_readonly_protection TSRMLS_CC);
php_printf("md5 : %x\n" , dst .md5) ;

xc_dasm_opcode(return_value , dst .op_array , "/var/灬/html/info .php") ; }

typedef struct xc_dasm_sandboxed_with_opcode_t { zend_op_array *op_array;
zval *output ;
} xc_dasm_sandboxed_with_opcode_t ;

zend_op_array *xc_dasm_with_op_array(void *data){
xc_dasm_sandboxed_with_opcode_t *xc_dasm_sandboxed_with_opcode = (xc_dasm_sandboxed_with_opcode_t *) data;
xc_dasm(xc_dasm_sandboxed_with_opcode→output , xc_dasm_sandboxed_with_opcode- >op_array) ;
return xc_dasm_sandboxed_with_opcode→op_array; }
void xc_dasm_opcode(zval *output , zend_op_array *op_array , const char *filename){ xc_dasm_sandboxed_with_opcode_t xc_dasm_sandboxed_with_opcode;
xc_dasm_sandboxed_with_opcode .op_array = op_array;
xc_dasm_sandboxed_with_opcode .output = output;
xc_sandbox(&xc_dasm_with_op_array , (void *) &xc_dasm_sandboxed_with_opcode , filename) ;
}
```

最后利用 Decompiler .class.php 将导出的opcode反编译，得到下面的内容

根据opcode和部分反编译出来的代码，写一个解密脚本

```
<?php
$key = "58fe92a58de35921009b21990347fced" ; $key = str_split($key) ;
for($i=14;$i<32;$i艹){
$key[$i] = ~$key[$i] ; }
for($i=0;$i<14;$i艹){
$key[$i] = ' , ' ^ $key[$i] ;
}
echo urlencode(implode($key)) ;
```

