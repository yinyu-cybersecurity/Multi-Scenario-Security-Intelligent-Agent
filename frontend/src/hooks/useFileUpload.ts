// frontend/src/hooks/useFileUpload.ts

import { useCallback } from 'react';
import { useAppStore } from '../store/useAppStore';

const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
const MAX_FILES = 5;

export function useFileUpload() {
  const { attachments, addAttachment, removeAttachment, clearAttachments, setDragging } = useAppStore();

  const validateFile = useCallback((file: File): string | null => {
    if (file.size > MAX_FILE_SIZE) {
      return `File ${file.name} exceeds 50MB limit`;
    }
    return null;
  }, []);

  const handleFiles = useCallback((files: FileList | File[]) => {
    const fileArray = Array.from(files);

    if (attachments.length + fileArray.length > MAX_FILES) {
      alert(`Maximum ${MAX_FILES} files allowed`);
      return;
    }

    for (const file of fileArray) {
      const error = validateFile(file);
      if (error) {
        alert(error);
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
    MAX_FILE_SIZE,
    MAX_FILES,
  };
}