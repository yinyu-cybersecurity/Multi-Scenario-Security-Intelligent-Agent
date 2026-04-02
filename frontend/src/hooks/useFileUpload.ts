// frontend/src/hooks/useFileUpload.ts

import { useCallback } from 'react';
import { useAppStore } from '../store/useAppStore';
import { buildHook, BuiltHook } from './hookFactory';

/**
 * 文件上传配置 - 镜像后端TOOL_DEFAULTS模式
 */
const FILE_UPLOAD_DEFAULTS = {
  maxFileSize: 50 * 1024 * 1024, // 50MB
  maxFiles: 5,
  allowedExtensions: [] as string[], // 空数组 = 不限制，AI自主判断
  validateMimeType: () => false, // CTF场景不过度限制
};

// 使用buildHook工厂创建配置
const fileUploadHook: BuiltHook = buildHook({
  name: 'FileUpload',
  ...FILE_UPLOAD_DEFAULTS,
});

export function useFileUpload() {
  const { attachments, addAttachment, removeAttachment, clearAttachments, setDragging } = useAppStore();

  const validateFile = useCallback((file: File): string | null => {
    // 仅验证大小，类型由AI自主判断（CTF场景）
    if (file.size > FILE_UPLOAD_DEFAULTS.maxFileSize) {
      return `File ${file.name} exceeds 50MB limit`;
    }
    return null;
  }, []);

  const handleFiles = useCallback((files: FileList | File[]) => {
    const fileArray = Array.from(files);

    if (attachments.length + fileArray.length > FILE_UPLOAD_DEFAULTS.maxFiles) {
      console.warn(`Maximum ${FILE_UPLOAD_DEFAULTS.maxFiles} files allowed`);
      return;
    }

    for (const file of fileArray) {
      const error = validateFile(file);
      if (error) {
        console.warn(error);
        continue;
      }

      addAttachment({
        id: '',
        name: file.name,
        size: file.size,
        type: file.type || 'application/octet-stream',
        file,
      });
    }
  }, [attachments.length, validateFile, addAttachment]);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    handleFiles(e.dataTransfer.files);
  }, [handleFiles, setDragging]);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(true);
  }, [setDragging]);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
  }, [setDragging]);

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      handleFiles(e.target.files);
    }
    e.target.value = '';
  }, [handleFiles]);

  const formatSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes}B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
  };

  return {
    attachments,
    addAttachment,
    removeAttachment,
    clearAttachments,
    handleDrop,
    handleDragOver,
    handleDragLeave,
    handleFileSelect,
    formatSize,
    maxFileSize: FILE_UPLOAD_DEFAULTS.maxFileSize,
    maxFiles: FILE_UPLOAD_DEFAULTS.maxFiles,
  };
}

// 导出配置供测试使用
export { FILE_UPLOAD_DEFAULTS, fileUploadHook };