// frontend/src/components/Console/MarkdownRenderer.tsx
/**
 * Markdown渲染器 - 支持代码高亮
 */

import React from 'react';

/**
 * 简单Markdown渲染器
 * 注意: 生产环境应使用 react-markdown + react-syntax-highlighter
 */
export const MarkdownRenderer: React.FC<{
  content: string;
}> = ({ content }) => {
  // 解析Markdown为简单HTML
  const renderMarkdown = (text: string): React.ReactNode => {
    // 代码块处理
    const codeBlockRegex = /```(\w+)?\n([\s\S]*?)```/g;

    const parts: React.ReactNode[] = [];
    let key = 0;

    // 处理代码块
    const codeBlockMatches: Array<{ start: number; end: number; lang: string; code: string }> = [];

    let match;
    while ((match = codeBlockRegex.exec(text)) !== null) {
      codeBlockMatches.push({
        start: match.index,
        end: match.index + match[0].length,
        lang: match[1] || '',
        code: match[2],
      });
    }

    // 构建渲染结果
    let currentPos = 0;

    for (const block of codeBlockMatches) {
      // 添加代码块前的文本
      if (block.start > currentPos) {
        const beforeText = text.slice(currentPos, block.start);
        parts.push(<span key={key++}>{renderInlineMarkdown(beforeText)}</span>);
      }

      // 添加代码块
      parts.push(
        <div key={key++} className="my-2">
          {block.lang && (
            <div className="text-xs text-gray-500 bg-gray-100 px-2 py-1 rounded-t">
              {block.lang}
            </div>
          )}
          <pre className={`bg-gray-900 text-gray-100 p-3 rounded text-xs overflow-x-auto ${block.lang ? 'rounded-t-none' : ''}`}>
            <code>{block.code}</code>
          </pre>
        </div>
      );

      currentPos = block.end;
    }

    // 添加剩余文本
    if (currentPos < text.length) {
      parts.push(<span key={key++}>{renderInlineMarkdown(text.slice(currentPos))}</span>);
    }

    return parts.length > 0 ? parts : text;
  };

  // 渲染行内Markdown
  const renderInlineMarkdown = (text: string): React.ReactNode => {
    // 简单处理行内代码
    const parts = text.split(/`([^`]+)`/);
    return parts.map((part, i) => {
      if (i % 2 === 1) {
        return (
          <code key={i} className="bg-gray-100 text-pink-600 px-1 py-0.5 rounded text-xs">
            {part}
          </code>
        );
      }
      return part;
    });
  };

  return (
    <div className="markdown-body">
      {renderMarkdown(content)}
    </div>
  );
};

export default MarkdownRenderer;