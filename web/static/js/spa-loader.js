/**
 * SPA 页面切换模块
 * 使用 History API + AJAX 实现无刷新页面切换
 */

(function() {
    const BASE_PATH = '/fisher_ctf_agent';
    const PAGES = ['monitor', 'modules', 'topology', 'rag'];

    let currentPath = window.location.pathname;
    let isLoading = false;

    // 初始化
    function init() {
        // 拦截导航点击
        document.addEventListener('click', handleNavClick);

        // 处理浏览器前进/后退
        window.addEventListener('popstate', handlePopState);

        // 更新当前页面的导航高亮
        updateNavHighlight();
    }

    // 处理导航点击
    function handleNavClick(e) {
        const link = e.target.closest('.nav-link');
        if (!link) return;

        const href = link.getAttribute('href');
        if (!href || !href.startsWith(BASE_PATH)) return;

        // 检查是否是页面导航
        const page = PAGES.find(p => href === `${BASE_PATH}/${p}` || href.startsWith(`${BASE_PATH}/${p}?`));
        if (page) {
            e.preventDefault();
            navigateTo(href);
        }
    }

    // 导航到新页面
    function navigateTo(url) {
        if (isLoading) return;
        if (url === currentPath) return;

        isLoading = true;
        currentPath = url;

        // 显示加载指示器
        showLoader();

        // 使用 fetch 加载页面内容
        fetch(url)
            .then(response => response.text())
            .then(html => {
                // 解析 HTML
                const parser = new DOMParser();
                const doc = parser.parseFromString(html, 'text/html');

                // 替换页面内容
                const newApp = doc.querySelector('#app');
                const currentApp = document.querySelector('#app');

                if (newApp && currentApp) {
                    // 保存滚动位置
                    const scrollPos = { x: window.scrollX, y: window.scrollY };

                    // 替换内容
                    currentApp.innerHTML = newApp.innerHTML;

                    // 更新页面标题
                    document.title = doc.title;

                    // 更新 URL
                    history.pushState({ path: url }, doc.title, url);

                    // 更新导航高亮
                    updateNavHighlight();

                    // 执行脚本
                    executeScripts(newApp);

                    // 恢复滚动位置（通常重置到顶部）
                    window.scrollTo(0, 0);
                }
            })
            .catch(error => {
                console.error('页面加载失败:', error);
                // 降级为传统导航
                window.location.href = url;
            })
            .finally(() => {
                isLoading = false;
                hideLoader();
            });
    }

    // 处理浏览器前进/后退
    function handlePopState(e) {
        if (e.state && e.state.path) {
            // 重新加载页面（简化处理）
            window.location.href = e.state.path;
        }
    }

    // 更新导航高亮
    function updateNavHighlight() {
        const currentPath = window.location.pathname;
        document.querySelectorAll('.nav-link').forEach(link => {
            const href = link.getAttribute('href');
            if (href === currentPath) {
                link.classList.add('active');
            } else {
                link.classList.remove('active');
            }
        });
    }

    // 显示加载指示器
    function showLoader() {
        // 可以添加加载动画
        document.body.style.cursor = 'wait';
    }

    // 隐藏加载指示器
    function hideLoader() {
        document.body.style.cursor = 'default';
    }

    // 执行新页面的脚本
    function executeScripts(container) {
        const scripts = container.querySelectorAll('script');
        scripts.forEach(oldScript => {
            const newScript = document.createElement('script');
            if (oldScript.src) {
                newScript.src = oldScript.src;
            } else {
                newScript.textContent = oldScript.textContent;
            }
            document.body.appendChild(newScript);
            // 移除临时脚本
            document.body.removeChild(newScript);
        });
    }

    // 页面加载完成后初始化
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // 导出函数供外部使用
    window.SPA = {
        navigateTo: navigateTo
    };
})();