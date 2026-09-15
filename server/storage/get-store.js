/**
 * server/storage/get-store.js
 *
 * 生产环境唯一的 Pages Blob Store 获取路径。
 *
 * 依据官方 https://pages.edgeone.ai/document/blob-storage 与本地 SDK
 * node_modules/@edgeone/pages-blob/dist/index.d.ts：在 Pages Functions 内
 * `getStore(name)` 会自动完成鉴权，无需传 projectId/token。SDK 对 store 名的
 * 校验为：非空、不含 `/` 与 `:`、只允许字母数字下划线连字符、UTF-8 不超过 64
 * 字节（见 dist/index.js 中的 store 名校验函数）。
 *
 * 这里不接受任何来自请求上下文的 store 注入。业务层（storeBatch/
 * handleAdminRequest）仍然接受 store 参数以便离线测试，但生产入口只能通过
 * 本模块取得真实 Store，避免出现可被请求影响的存储后门。
 */

import { getStore } from "@edgeone/pages-blob";

/** 环境变量名：Blob store 名称。 */
export const ENV_BLOB_STORE = "BLOB_STORE";

/** 未配置 BLOB_STORE 时使用的默认 store 名。 */
export const DEFAULT_BLOB_STORE_NAME = "edgeone-realtime-logs";

/** SDK 对 store 名的校验规则（与 SDK 实现保持一致，提前失败而不是等它抛）。 */
const STORE_NAME_PATTERN = /^[a-zA-Z0-9_-]+$/;

/**
 * 解析要使用的 store 名：优先取环境变量，缺失或为空时用默认名。
 * 名称非法时抛错，由调用方映射为配置类错误响应。
 *
 * @param {Record<string,string|undefined>} env
 * @returns {string}
 */
export function resolveStoreName(env) {
  const raw = env?.[ENV_BLOB_STORE];
  const name =
    typeof raw === "string" && raw.trim().length > 0
      ? raw.trim()
      : DEFAULT_BLOB_STORE_NAME;

  if (!STORE_NAME_PATTERN.test(name)) {
    throw new Error(
      `${ENV_BLOB_STORE} must match ${STORE_NAME_PATTERN} (letters, digits, underscore, hyphen)`
    );
  }
  if (Buffer.byteLength(name, "utf8") > 64) {
    throw new Error(`${ENV_BLOB_STORE} must be at most 64 bytes`);
  }
  return name;
}

/**
 * 取得真实的 Pages Blob Store。
 *
 * 未验证项：本函数在真实 Pages 运行时中的行为（能否成功取得凭据）只能在实际
 * 部署后确认；离线环境下 SDK 会因缺少部署凭据抛 MISSING_ENVIRONMENT。
 *
 * @param {Record<string,string|undefined>} env
 * @returns {import("@edgeone/pages-blob").Store}
 */
export function getLogStore(env) {
  return getStore(resolveStoreName(env));
}
