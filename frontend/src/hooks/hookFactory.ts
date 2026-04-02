// frontend/src/hooks/hookFactory.ts

/**
 * Hook默认配置 - 镜像后端TOOL_DEFAULTS
 * 保守策略：默认禁用重连，需要显式启用
 */
const HOOK_DEFAULTS = {
  shouldReconnect: () => false,
  reconnectDelay: () => 3000,
  maxReconnectAttempts: () => 5,
  timeout: () => 60000,
  validateInput: () => true,
  onError: (error: Error) => console.error('[Hook Error]', error),
  onConnect: () => {},
  onDisconnect: () => {},
};

/**
 * Hook定义接口
 */
export interface HookDefinition {
  name: string;
  url?: string;
  shouldReconnect?: () => boolean;
  reconnectDelay?: () => number;
  maxReconnectAttempts?: () => number;
  timeout?: () => number;
  validateInput?: () => boolean;
  onError?: (error: Error) => void;
  onConnect?: () => void;
  onDisconnect?: () => void;
}

/**
 * 构建后的Hook配置
 */
export interface BuiltHook {
  name: string;
  url: string;
  shouldReconnect: () => boolean;
  reconnectDelay: () => number;
  maxReconnectAttempts: () => number;
  timeout: () => number;
  validateInput: () => boolean;
  onError: (error: Error) => void;
  onConnect: () => void;
  onDisconnect: () => void;
  userFacingName: () => string;
}

/**
 * buildHook工厂函数 - 镜像后端buildTool模式
 *
 * @example
 * const wsHook = buildHook({
 *   name: 'WebSocket',
 *   url: 'ws://localhost:8000/ws',
 *   shouldReconnect: () => true,
 * });
 */
export function buildHook(definition: HookDefinition): BuiltHook {
  return {
    ...HOOK_DEFAULTS,
    url: definition.url || '',
    ...definition,
    userFacingName: () => definition.name,
  };
}

export { HOOK_DEFAULTS };