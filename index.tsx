/**
 * Unified LLM Gateway v3.0.1 (Production Fixes)
 * Features: Smart Path Resolution, Robust Streaming, Secure Admin
 */

const VERSION = '3.0.1';
const SESSION_COOKIE_NAME = 'LLM_GATEWAY_SESSION';

// ================= 1. 核心入口 =================

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") return handleOptions(request);

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // --- Public API ---
      if (path === '/v1/chat/completions' && request.method === 'POST') {
        return await handleChatCompletions(request, env, ctx);
      }
      if (path === '/v1/models' && request.method === 'GET') {
        return await handleListModels(request, env);
      }
      if (path === '/health') {
        return createResponse({ status: 'ok', version: VERSION });
      }

      // --- Admin Interface & API ---
      if (path.startsWith('/admin') || path.startsWith('/api/admin')) {
        return await handleAdmin(request, env, path);
      }

      return createResponse({ error: 'Not Found' }, 404);
    } catch (e) {
      console.error("[Fatal Error]", e);
      return createResponse({ error: { message: e.message || "Internal Gateway Error", type: 'internal_server_error' } }, 500);
    }
  }
};

// ================= 2. 聊天处理核心 (Gateway) =================

async function handleChatCompletions(request, env, ctx) {
  // 1. 客户端鉴权
  const client = await authenticateClient(request, env);
  if (!client) return createResponse({ error: { message: 'Invalid API Key', type: 'invalid_request_error', code: 401 } }, 401);

  // 2. 解析请求
  let body;
  try { body = await request.json(); } catch(e) { return createResponse({ error: { message: 'Invalid JSON', type: 'invalid_request_error', code: 400 } }, 400); }

  const originalModel = body.model || 'gpt-3.5-turbo';
  const isStream = body.stream === true;

  // 3. 模型路由逻辑 (前缀分离)
  let routePrefix = originalModel;
  let realModel = originalModel;
  
  if (originalModel.includes(':')) {
    const parts = originalModel.split(':');
    // openai:gpt-4o -> realModel: gpt-4o
    realModel = parts.slice(1).join(':'); 
    routePrefix = realModel; 
  }

  // 数据库查找路由
  const route = await findRouteForModel(env, routePrefix);
  if (!route) {
    return createResponse({ error: { message: `No route configured for model: ${originalModel}`, type: 'routing_error', code: 404 } }, 404);
  }

  // 4. 解密上游 Key
  const apiKey = await decrypt(route.api_key_enc, route.iv, env.MASTER_KEY);
  if (!apiKey) return createResponse({ error: { message: 'Provider configuration error (key decryption failed)', type: 'config_error' } }, 500);

  // 5. 记录开始时间 & 更新客户端活跃状态 (Fix: Ensure function exists)
  const startTime = Date.now();
  ctx.waitUntil(updateClientUsage(env, client.id));

  try {
    // 6. 转发请求
    const response = await dispatchProvider(route, apiKey, body, realModel, isStream);
    
    // 异步日志
    ctx.waitUntil(logRequest(env, client.name, route.name, originalModel, isStream, response.status, Date.now() - startTime));
    
    return response;
  } catch (e) {
    console.error("Dispatch Error:", e);
    // 保持 502 Bad Gateway 语义
    return createResponse({ error: { message: `Upstream error: ${e.message}`, type: 'upstream_error', code: 502 } }, 502);
  }
}

async function dispatchProvider(provider, apiKey, body, realModel, isStream) {
  const headers = { 'Content-Type': 'application/json' };
  
  // [Fix 2] 使用智能路径解析
  const targetUrl = resolveUrl(provider.base_url, provider.path, provider.type, realModel, isStream, apiKey);

  // >>> A. OpenAI (Official & Loose Compatible) <<<
  if (provider.type === 'openai' || provider.type === 'openai_compat_loose') {
    headers['Authorization'] = `Bearer ${apiKey}`;
    const newBody = { ...body, model: realModel };

    const resp = await fetch(targetUrl, { method: 'POST', headers, body: JSON.stringify(newBody) });
    
    if (!resp.ok) return proxyErrorResponse(resp, provider.name);

    if (isStream) {
        // [Fix 3] 统一流解析器
        return universalStreamToOpenAI(resp, realModel);
    }
    
    const data = await resp.json();
    return createResponse(normalizeOpenAIResponse(data, realModel));
  }

  // >>> B. Anthropic Claude <<<
  else if (provider.type === 'anthropic') {
    headers['x-api-key'] = apiKey;
    headers['anthropic-version'] = '2023-06-01';
    
    const anthropicBody = convertOpenAIToAnthropic(body, realModel, isStream);
    const resp = await fetch(targetUrl, { method: 'POST', headers, body: JSON.stringify(anthropicBody) });
    
    if (!resp.ok) return proxyErrorResponse(resp, provider.name);

    if (isStream) return handleAnthropicStream(resp, realModel); // 转换为 OpenAI Chunk
    
    const data = await resp.json();
    return createResponse(convertAnthropicToOpenAI(data, realModel));
  }

  // >>> C. Gemini (Google) <<<
  else if (provider.type === 'gemini') {
    // API Key 已经在 resolveUrl 中拼接到 URL 参数里了
    const geminiBody = convertOpenAIToGemini(body);
    const resp = await fetch(targetUrl, { method: 'POST', headers, body: JSON.stringify(geminiBody) });

    if (!resp.ok) return proxyErrorResponse(resp, provider.name);

    if (isStream) return universalStreamToOpenAI(resp, realModel); // Gemini 流通常是 JSON 数组片段

    const data = await resp.json();
    return createResponse(convertGeminiToOpenAI(data, realModel));
  }

  throw new Error(`Unknown provider type: ${provider.type}`);
}

// ================= 3. 智能路径与错误处理 (修复核心) =================

// [Fix 2] 智能 Endpoint 组装
function resolveUrl(baseUrl, userPath, type, model, isStream, apiKey) {
  let url = baseUrl.replace(/\/+$/, ''); // 去除 Base URL 尾部斜杠
  let path = (userPath || '').trim();

  // OpenAI / 兼容中转
  if (type === 'openai' || type === 'openai_compat_loose') {
    const defaultEndpoint = '/v1/chat/completions';

    // 1. 空路径 -> 默认
    if (!path) return `${url}${defaultEndpoint}`;

    // 2. 目录型路径 (v1, /v1, /v1/) -> 补全剩余
    // 正则匹配: 可选/, v1, 可选/ 结尾
    if (/^\/?v1\/?$/.test(path)) {
      return `${url}/v1/chat/completions`;
    }

    // 3. 完整 Endpoint -> 原样使用 (自动补前导 /)
    if (path.includes('/chat/completions')) {
      return path.startsWith('/') ? `${url}${path}` : `${url}/${path}`;
    }

    // 4. 其他情况 (比如 /beta) -> 简单拼接并假设用户想要补全 chat/completions
    // 如果用户填的是 /api，变成 /api/chat/completions
    const cleanPath = path.startsWith('/') ? path : `/${path}`;
    return `${url}${cleanPath.replace(/\/$/, '')}/chat/completions`;
  }

  // Anthropic
  if (type === 'anthropic') {
    if (!path || /^\/?v1\/?$/.test(path)) return `${url}/v1/messages`;
    return path.startsWith('/') ? `${url}${path}` : `${url}/${path}`;
  }

  // Gemini
  if (type === 'gemini') {
    const method = isStream ? 'streamGenerateContent' : 'generateContent';
    // 默认 v1beta
    let version = 'v1beta';
    // 如果用户填了 path (如 v1)，则使用用户填的
    if (path) version = path.replace(/^\//, '').replace(/\/$/, '');
    
    return `${url}/${version}/models/${model}:${method}?key=${apiKey}`;
  }

  return url;
}

// 错误透传
async function proxyErrorResponse(resp, providerName) {
    let errorBody: any = {};
    try {
        const text = await resp.text();
        try { errorBody = JSON.parse(text); } catch(e) { errorBody = { message: text }; }
    } catch(e) { errorBody = { message: "Upstream error (unreadable)" }; }

    return createResponse({
        error: {
            message: errorBody.error?.message || errorBody.message || "Upstream Error",
            type: "upstream_error",
            code: resp.status,
            upstream: providerName,
            details: errorBody
        }
    }, resp.status);
}

// ================= 4. 通用流处理与转换 (Fix 3 & 4) =================

// [Fix 3] 通用流解析器：防止重复 DONE，支持多种格式
function universalStreamToOpenAI(response, model) {
    const { readable, writable } = new TransformStream();
    const writer = writable.getWriter();
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    let hasSentDone = false; // [Fix] 标志位

    (async () => {
        const reader = response.body.getReader();
        let buffer = '';
        try {
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                buffer += decoder.decode(value, { stream: true });
                
                // 1. 处理 SSE / JSONL (按行)
                const lines = buffer.split('\n');
                buffer = lines.pop(); // 保留未完成行

                for (const line of lines) {
                    const trimmed = line.trim();
                    if (!trimmed) continue;

                    if (trimmed === 'data: [DONE]' || trimmed === '[DONE]') {
                        if (!hasSentDone) {
                            await writer.write(encoder.encode('data: [DONE]\n\n'));
                            hasSentDone = true;
                        }
                        continue;
                    }

                    let jsonStr = '';
                    if (trimmed.startsWith('data: ')) jsonStr = trimmed.slice(6);
                    else if (trimmed.startsWith('{')) jsonStr = trimmed;

                    if (jsonStr) {
                        try {
                            const data = JSON.parse(jsonStr);
                            await emitChunk(writer, encoder, data, model);
                        } catch (e) { }
                    }
                }
                
                // 2. 处理数组碎片 (Gemini/OneAPI 可能返回无换行的数组流)
                buffer = buffer.trimStart();
                if (buffer.startsWith('[') || buffer.startsWith(',') || buffer.startsWith('{')) {
                     const { remaining, objects } = extractObjects(buffer);
                     if (objects.length > 0) {
                         buffer = remaining;
                         for (const data of objects) {
                             await emitChunk(writer, encoder, data, model);
                         }
                     }
                }
            }

            // 处理缓冲区剩余
            if (buffer.trim()) {
                 try {
                     const clean = buffer.trim().replace(/^data: /, '');
                     const data = JSON.parse(clean);
                     await emitChunk(writer, encoder, data, model);
                 } catch(e) {}
            }

            if (!hasSentDone) {
                await writer.write(encoder.encode('data: [DONE]\n\n'));
            }
        } catch (e) {
            // 出错时发送错误块，而不是断开连接，以便前端感知
            const errChunk = createOpenAIChunk(`\n\n[Gateway Error: ${e.message}]`, model, 'stop');
            await writer.write(encoder.encode(`data: ${JSON.stringify(errChunk)}\n\n`));
            if (!hasSentDone) await writer.write(encoder.encode('data: [DONE]\n\n'));
        } finally {
            writer.close();
        }
    })();

    return new Response(readable, { headers: { 'Content-Type': 'text/event-stream', ...corsHeaders() } });
}

// [Fix 4] 增强文本提取 (用于流和非流)
function extractTextFromAnywhere(data) {
    if (!data) return '';
    // 1. OpenAI Stream
    if (data.choices?.[0]?.delta?.content) return data.choices[0].delta.content;
    // 2. OpenAI Non-Stream (或流中混入完整 Message)
    if (data.choices?.[0]?.message?.content) {
        const c = data.choices[0].message.content;
        return typeof c === 'string' ? c : (Array.isArray(c) ? c.map(p=>p.text||'').join('') : '');
    }
    // 3. Legacy / DeepSeek
    if (data.choices?.[0]?.text) return data.choices[0].text;
    // 4. Anthropic / OneAPI Top-level
    if (data.text) return data.text;
    if (data.output_text) return data.output_text;
    // 5. Anthropic Content Array
    if (Array.isArray(data.content) && data.content[0]?.text) return data.content[0].text;
    if (typeof data.content === 'string') return data.content;
    // 6. Gemini
    if (data.candidates?.[0]?.content?.parts?.[0]?.text) return data.candidates[0].content.parts[0].text;
    
    return '';
}

async function emitChunk(writer, encoder, data, model) {
    const text = extractTextFromAnywhere(data);
    const finish_reason = data.choices?.[0]?.finish_reason || data.finish_reason || null;
    
    if (text || finish_reason) {
        const chunk = createOpenAIChunk(text, model, finish_reason);
        await writer.write(encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`));
    }
}

function createOpenAIChunk(text, model, finish_reason = null) {
    return {
        id: `chatcmpl-${Date.now()}`,
        object: 'chat.completion.chunk',
        created: Math.floor(Date.now() / 1000),
        model: model,
        choices: [{ 
            index: 0, 
            delta: text ? { content: text } : {}, 
            finish_reason: finish_reason 
        }]
    };
}

// [Fix 4 & 5] 非流响应标准化
function normalizeOpenAIResponse(data, model) {
  // 如果已经是标准结构，直接返回
  if (data?.choices?.[0]?.message?.role === 'assistant') return data;

  const content = extractTextFromAnywhere(data);
  const finish_reason = data.stop_reason || data.choices?.[0]?.finish_reason || 'stop';

  return {
    id: data.id || `chatcmpl-${Date.now()}`,
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model: model,
    choices: [{
      index: 0,
      message: { role: 'assistant', content: content || '' },
      finish_reason: finish_reason
    }],
    usage: data.usage || { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 }
  };
}

// 辅助: JSON 提取
function extractObjects(str) {
    let startIdx = 0; let openBraces = 0; let inString = false; let objects = [];
    for (let i = 0; i < str.length; i++) {
        const char = str[i];
        if (char === '"' && str[i-1] !== '\\') inString = !inString;
        if (!inString) {
            if (char === '{') { if (openBraces === 0) startIdx = i; openBraces++; }
            if (char === '}') { openBraces--; if (openBraces === 0) { try { objects.push(JSON.parse(str.substring(startIdx, i + 1))); } catch(e){} startIdx = i + 1; } }
        }
    }
    return { remaining: str.slice(startIdx), objects };
}

// --- Anthropic Logic ---
function convertOpenAIToAnthropic(body, model, stream) {
  let system = ''; const messages = [];
  for (const msg of body.messages) {
    if (msg.role === 'system') system += (msg.content || '') + '\n';
    else messages.push({ role: msg.role === 'assistant' ? 'assistant' : 'user', content: msg.content || '' });
  }
  return { model, messages, system: system.trim() || undefined, max_tokens: body.max_tokens || 4096, stream, temperature: body.temperature };
}

function convertAnthropicToOpenAI(data, model) {
  // 直接调用 standardize
  return normalizeOpenAIResponse(data, model);
}

function handleAnthropicStream(response, model) {
    // 复用 universal parser，只需要把 Anthropic SSE 转成 OpenAI 结构
    // 这里简单做一个转换流，或者利用 universalParser 的兼容性
    // 为了稳健，我们使用专门的转换逻辑，但输出到 universal 兼容格式
    const { readable, writable } = new TransformStream();
    const writer = writable.getWriter();
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    let hasSentDone = false;

    (async () => {
        const reader = response.body.getReader();
        let buffer = '';
        try {
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                buffer += decoder.decode(value, { stream: true });
                const lines = buffer.split('\n');
                buffer = lines.pop();

                for (const line of lines) {
                    if (line.startsWith('data: ')) {
                        try {
                            const event = JSON.parse(line.slice(6));
                            if (event.type === 'content_block_delta' && event.delta?.text) {
                                const chunk = createOpenAIChunk(event.delta.text, model);
                                await writer.write(encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`));
                            }
                        } catch(e) {}
                    }
                }
            }
            if (!hasSentDone) await writer.write(encoder.encode('data: [DONE]\n\n'));
        } catch(e) { /* error handling */ }
        finally { writer.close(); }
    })();
    return new Response(readable, { headers: { 'Content-Type': 'text/event-stream', ...corsHeaders() } });
}

// --- Gemini Logic ---
function convertOpenAIToGemini(body) {
  const contents = []; let systemInstruction = undefined;
  for (const msg of body.messages) {
    if (msg.role === 'system') systemInstruction = { parts: [{ text: msg.content }] };
    else contents.push({ role: msg.role === 'assistant' ? 'model' : 'user', parts: [{ text: msg.content }] });
  }
  if (contents.length > 0 && contents[0].role === 'model') contents.unshift({ role: 'user', parts: [{ text: ' ' }] });
  return { contents, systemInstruction, generationConfig: { maxOutputTokens: body.max_tokens, temperature: body.temperature } };
}

function convertGeminiToOpenAI(data, model) {
  return normalizeOpenAIResponse(data, model);
}


// ================= 5. 管理后台 (Fix 5: Security) =================

async function handleAdmin(request, env, path) {
  const session = await verifySession(request, env);
  
  if (path === '/api/admin/login' && request.method === 'POST') {
    const { password } = await request.json();
    if (password === env.ADMIN_PASSWORD) {
        const cookie = await createSessionCookie(env);
        return createResponse({ success: true }, 200, { 'Set-Cookie': cookie });
    }
    return createResponse({ error: 'Wrong password' }, 401);
  }

  if (path === '/admin/login') return new Response(ui_template_str.replace('{{VIEW}}', 'login'), { headers: { 'Content-Type': 'text/html' } });

  if (!session) {
    if (path.startsWith('/api/')) return createResponse({ error: 'Unauthorized' }, 401);
    return Response.redirect(new URL('/admin/login', request.url).toString(), 302);
  }

  if (path === '/admin' || path === '/admin/') return new Response(ui_template_str.replace('{{VIEW}}', 'dashboard'), { headers: { 'Content-Type': 'text/html' } });

  // [Fix 5] 安全查询: 不返回敏感字段
  if (path === '/api/admin/providers') {
    if (request.method === 'GET') {
        const { results } = await env.DB.prepare('SELECT id, name, type, base_url, path, is_enabled, created_at FROM providers ORDER BY id DESC').all();
        return createResponse(results);
    }
    if (request.method === 'POST') {
        const d = await request.json();
        const enc = await encrypt(d.key, env.MASTER_KEY);
        await env.DB.prepare('INSERT INTO providers (name, type, base_url, path, api_key_enc, iv, is_enabled) VALUES (?, ?, ?, ?, ?, ?, 1)')
            .bind(d.name, d.type, d.base_url, d.path, enc.text, enc.iv).run();
        return createResponse({ success: true });
    }
  }
  if (path.startsWith('/api/admin/providers/') && request.method === 'DELETE') {
      const id = path.split('/').pop();
      await env.DB.prepare('DELETE FROM providers WHERE id = ?').bind(id).run();
      return createResponse({ success: true });
  }

  if (path === '/api/admin/routes') {
    if (request.method === 'GET') {
        const { results } = await env.DB.prepare(`
            SELECT r.id, r.prefix, p.name as provider_name 
            FROM routes r JOIN providers p ON r.provider_id = p.id
            ORDER BY length(r.prefix) DESC
        `).all();
        return createResponse(results);
    }
    if (request.method === 'POST') {
        const d = await request.json();
        await env.DB.prepare('INSERT INTO routes (prefix, provider_id) VALUES (?, ?)').bind(d.prefix, d.provider_id).run();
        return createResponse({ success: true });
    }
  }
  if (path.startsWith('/api/admin/routes/') && request.method === 'DELETE') {
      const id = path.split('/').pop();
      await env.DB.prepare('DELETE FROM routes WHERE id = ?').bind(id).run();
      return createResponse({ success: true });
  }

  if (path === '/api/admin/clients') {
    if (request.method === 'GET') {
        const { results } = await env.DB.prepare('SELECT id, name, key_prefix, last_used_at, is_active, created_at FROM clients ORDER BY id DESC').all();
        return createResponse(results);
    }
    if (request.method === 'POST') {
        const { name } = await request.json();
        const rawKey = 'sk-gw-' + crypto.randomUUID().replace(/-/g, '');
        const keyHash = await hashSHA256(rawKey);
        const prefix = rawKey.substring(0, 10);
        await env.DB.prepare('INSERT INTO clients (name, key_hash, key_prefix, is_active) VALUES (?, ?, ?, 1)').bind(name, keyHash, prefix).run();
        return createResponse({ success: true, raw_key: rawKey }); 
    }
  }
  if (path.startsWith('/api/admin/clients/') && request.method === 'DELETE') {
      const id = path.split('/').pop();
      await env.DB.prepare('DELETE FROM clients WHERE id = ?').bind(id).run();
      return createResponse({ success: true });
  }

  return createResponse({ error: 'Not Found' }, 404);
}

// ================= 6. 工具函数 (Fix 1: Add Missing Function) =================

// [Fix 1] 实现客户端用量更新
async function updateClientUsage(env, id) {
    try {
        await env.DB.prepare('UPDATE clients SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?').bind(id).run();
    } catch(e) { /* ignore DB update errors to avoid blocking chat */ }
}

function createResponse(body, status = 200, extraHeaders = {}) {
    const headers = { 
        'Content-Type': 'application/json',
        ...corsHeaders(), 
        ...extraHeaders 
    };
    return new Response(JSON.stringify(body), { status, headers });
}

function handleOptions(request) {
    return new Response(null, { headers: corsHeaders() });
}

function corsHeaders() {
    return {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, DELETE',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-api-key, anthropic-version',
    };
}

async function authenticateClient(request, env) {
    const h = request.headers.get('Authorization');
    if (!h || !h.startsWith('Bearer ')) return null;
    const key = h.split(' ')[1];
    const keyHash = await hashSHA256(key);
    return await env.DB.prepare('SELECT * FROM clients WHERE key_hash = ? AND is_active = 1').bind(keyHash).first();
}

async function findRouteForModel(env, modelPrefix) {
    const { results } = await env.DB.prepare(`
        SELECT r.*, p.name, p.type, p.base_url, p.path, p.api_key_enc, p.iv 
        FROM routes r JOIN providers p ON r.provider_id = p.id 
        WHERE p.is_enabled = 1
    `).all();
    const matched = results.filter(r => modelPrefix.startsWith(r.prefix)).sort((a,b) => b.prefix.length - a.prefix.length);
    return matched[0];
}

async function logRequest(env, cName, pName, model, isStream, status, dur) {
    try {
        await env.DB.prepare('INSERT INTO access_logs (client_name, provider_name, model, is_stream, status, duration_ms) VALUES (?,?,?,?,?,?)')
        .bind(cName, pName, model, isStream?1:0, status, dur).run();
    } catch(e) {}
}

async function handleListModels(request, env) {
    const { results } = await env.DB.prepare('SELECT prefix FROM routes').all();
    const data = [
        { id: "gpt-4o", object: "model", owned_by: "gateway" },
        { id: "claude-3-5-sonnet", object: "model", owned_by: "gateway" },
        { id: "gemini-1.5-pro", object: "model", owned_by: "gateway" },
    ];
    results.forEach(r => data.push({ id: `${r.prefix}...`, object: "model", owned_by: "gateway" }));
    return createResponse({ object: "list", data });
}

// --- Crypto Utils ---
async function hashSHA256(text) {
    const buf = new TextEncoder().encode(text);
    const hash = await crypto.subtle.digest('SHA-256', buf);
    return Array.from(new Uint8Array(hash)).map(b=>b.toString(16).padStart(2,'0')).join('');
}

async function getAESKey(secret) {
    const enc = new TextEncoder();
    const keyMat = await crypto.subtle.importKey("raw", enc.encode(secret), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: enc.encode("fixed-salt"), iterations: 100000, hash: "SHA-256" },
        keyMat, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
}

async function encrypt(text, secret) {
    const key = await getAESKey(secret);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(text));
    return { text: btoa(String.fromCharCode(...new Uint8Array(ct))), iv: btoa(String.fromCharCode(...iv)) };
}

async function decrypt(txt, ivStr, secret) {
    try {
        const key = await getAESKey(secret);
        const ct = Uint8Array.from(atob(txt), c=>c.charCodeAt(0));
        const iv = Uint8Array.from(atob(ivStr), c=>c.charCodeAt(0));
        const dec = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
        return new TextDecoder().decode(dec);
    } catch(e) { return null; }
}

async function getHMACKey(secret) {
    return crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

async function createSessionCookie(env) {
    const exp = Date.now() + 86400 * 1000; 
    const payload = btoa(JSON.stringify({ role: 'admin', exp }));
    const secret = env.SESSION_SECRET || env.MASTER_KEY; 
    const key = await getHMACKey(secret);
    const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
    const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
    return `${SESSION_COOKIE_NAME}=${payload}.${sigB64}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`;
}

async function verifySession(request, env) {
    const cookie = request.headers.get('Cookie');
    if (!cookie) return false;
    const match = cookie.match(new RegExp(`${SESSION_COOKIE_NAME}=([^;]+)`));
    if (!match) return false;
    const [payloadB64, sigB64] = match[1].split('.');
    if (!payloadB64 || !sigB64) return false;
    const secret = env.SESSION_SECRET || env.MASTER_KEY;
    const key = await getHMACKey(secret);
    const sig = Uint8Array.from(atob(sigB64), c=>c.charCodeAt(0));
    const valid = await crypto.subtle.verify("HMAC", key, sig, new TextEncoder().encode(payloadB64));
    if (!valid) return false;
    try { const payload = JSON.parse(atob(payloadB64)); return payload.exp > Date.now(); } catch(e) { return false; }
}

// ================= 7. Admin UI =================
const ui_template_str = `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Gateway Admin</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>
</head>
<body class="bg-gray-100 text-gray-800 font-sans">
<div id="app" class="min-h-screen">
  <div v-if="view === 'login'" class="flex items-center justify-center h-screen">
    <div class="bg-white p-8 rounded shadow-lg w-96">
      <h2 class="text-2xl font-bold mb-6 text-center text-blue-900">Gateway Login</h2>
      <input v-model="password" type="password" @keyup.enter="login" placeholder="Password" class="w-full border p-3 mb-4 rounded focus:ring focus:ring-blue-200 outline-none">
      <button @click="login" class="w-full bg-blue-600 text-white p-3 rounded font-bold hover:bg-blue-700 transition">Enter</button>
    </div>
  </div>

  <div v-if="view === 'dashboard'" class="max-w-5xl mx-auto p-4">
    <header class="flex justify-between items-center mb-8 py-4 border-b border-gray-200">
      <div><h1 class="text-3xl font-extrabold text-slate-800">Unified Gateway</h1><p class="text-sm text-gray-500">v${VERSION}</p></div>
    </header>

    <div class="grid grid-cols-1 gap-8">
      <section class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <h2 class="text-xl font-bold mb-4 flex items-center">🔌 Providers</h2>
        <div class="space-y-3">
          <div v-for="p in providers" :key="p.id" class="flex justify-between items-center bg-slate-50 p-4 rounded-lg border border-slate-100">
            <div>
              <div class="font-bold text-lg">{{ p.name }} <span class="text-xs ml-2 bg-blue-100 text-blue-800 px-2 py-0.5 rounded-full uppercase">{{ p.type }}</span></div>
              <div class="text-xs text-gray-500 font-mono mt-1">{{ p.base_url }} (Path: {{ p.path || 'Auto' }})</div>
            </div>
            <button @click="delProvider(p.id)" class="text-red-500 hover:text-red-700 font-medium text-sm">Remove</button>
          </div>
        </div>
        <div class="mt-6 pt-4 border-t grid grid-cols-1 md:grid-cols-2 gap-3">
          <input v-model="newProv.name" placeholder="Name" class="border p-2 rounded">
          <select v-model="newProv.type" class="border p-2 rounded">
            <option value="openai">OpenAI (Official)</option>
            <option value="openai_compat_loose">Compat (OneAPI/Relay)</option>
            <option value="anthropic">Anthropic (Claude)</option>
            <option value="gemini">Gemini (Google)</option>
          </select>
          <input v-model="newProv.base_url" placeholder="Base URL (e.g. https://api.openai.com)" class="border p-2 rounded col-span-2">
          <input v-model="newProv.path" placeholder="Path (Optional, e.g. /v1)" class="border p-2 rounded col-span-2">
          <input v-model="newProv.key" type="password" placeholder="API Key" class="border p-2 rounded col-span-2">
          <button @click="addProvider" class="bg-emerald-600 text-white p-2 rounded col-span-2 font-bold hover:bg-emerald-700">Add Provider</button>
        </div>
      </section>

      <section class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <h2 class="text-xl font-bold mb-4 flex items-center">🔀 Routes</h2>
        <div class="space-y-2">
          <div v-for="r in routes" :key="r.id" class="flex justify-between items-center border-b border-gray-100 py-3 last:border-0">
             <div class="flex items-center">
               <span class="font-mono bg-amber-100 text-amber-800 px-2 py-1 rounded text-sm mr-3">{{ r.prefix }}*</span>
               <span class="text-gray-400">➜</span>
               <span class="ml-3 font-semibold">{{ r.provider_name }}</span>
             </div>
             <button @click="delRoute(r.id)" class="text-red-500 hover:text-red-700 text-sm">Remove</button>
          </div>
        </div>
        <div class="flex gap-3 mt-4">
          <input v-model="newRoute.prefix" placeholder="Prefix (e.g. gpt-)" class="border p-2 rounded flex-1">
          <select v-model="newRoute.provider_id" class="border p-2 rounded flex-1">
            <option v-for="p in providers" :value="p.id">{{ p.name }}</option>
          </select>
          <button @click="addRoute" class="bg-blue-600 text-white px-6 py-2 rounded font-bold hover:bg-blue-700">Add Route</button>
        </div>
      </section>

      <section class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <h2 class="text-xl font-bold mb-4 flex items-center">🔑 Client Keys</h2>
        <div v-if="newKey" class="mb-6 bg-green-50 border border-green-200 p-4 rounded-lg">
          <p class="text-green-800 font-bold mb-1">Success! Copy Key:</p>
          <code class="block bg-white border p-3 rounded text-lg select-all break-all">{{ newKey }}</code>
        </div>
        <div class="space-y-2 mb-4">
           <div v-for="c in clients" :key="c.id" class="flex justify-between items-center bg-gray-50 p-3 rounded border border-gray-100">
             <div>
               <div class="font-bold text-gray-800">{{ c.name }}</div>
               <div class="text-xs text-gray-500 mt-1">Prefix: {{ c.key_prefix }}... | Active: {{ c.is_active }}</div>
             </div>
             <button @click="delClient(c.id)" class="text-red-500 hover:text-red-700 text-sm">Revoke</button>
           </div>
        </div>
        <div class="flex gap-3">
          <input v-model="newClientName" placeholder="Client Name" class="border p-2 rounded flex-1">
          <button @click="addClient" class="bg-purple-600 text-white px-6 py-2 rounded font-bold hover:bg-purple-700">Generate</button>
        </div>
      </section>
    </div>
  </div>
</div>
<script>
const { createApp, ref, onMounted } = Vue;
createApp({
  setup() {
    const view = ref('{{VIEW}}'); const password = ref(''); const newKey = ref('');
    const providers = ref([]); const routes = ref([]); const clients = ref([]);
    const newProv = ref({name:'',type:'openai',base_url:'',path:'',key:''});
    const newRoute = ref({prefix:'',provider_id:null}); const newClientName = ref('');

    const api = async (url, method='GET', body=null) => {
        const r = await fetch(url, { method, headers: {'Content-Type':'application/json'}, body: body?JSON.stringify(body):null });
        if(r.status===401) { location.href='/admin/login'; return; }
        return r.json();
    };

    const login = async () => { if((await api('/api/admin/login','POST',{password:password.value})).success) location.reload(); else alert('Failed'); };
    const load = async () => {
        if(view.value!=='dashboard') return;
        providers.value=await api('/api/admin/providers');
        routes.value=await api('/api/admin/routes');
        clients.value=await api('/api/admin/clients');
    };

    const addProvider = async () => { await api('/api/admin/providers','POST',newProv.value); newProv.value={name:'',type:'openai',base_url:'',path:'',key:''}; load(); };
    const delProvider = async (id) => { if(confirm('Sure?')) await api('/api/admin/providers/'+id,'DELETE'); load(); };
    const addRoute = async () => { await api('/api/admin/routes','POST',newRoute.value); newRoute.value.prefix=''; load(); };
    const delRoute = async (id) => { await api('/api/admin/routes/'+id,'DELETE'); load(); };
    const addClient = async () => { const r=await api('/api/admin/clients','POST',{name:newClientName.value}); newKey.value=r.raw_key; newClientName.value=''; load(); };
    const delClient = async (id) => { if(confirm('Revoke?')) await api('/api/admin/clients/'+id,'DELETE'); load(); };

    onMounted(load);
    return { view,password,login,providers,routes,clients,newProv,addProvider,delProvider,newRoute,addRoute,delRoute,newClientName,newKey,addClient,delClient };
  }
}).mount('#app');
</script>
</body>
</html>
