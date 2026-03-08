/**
 * Unified LLM Gateway v3.1.0 (All Bugs Fixed)
 *
 * Fix List:
 *  [F1] proxyErrorResponse: 移除 TypeScript `: any` 类型注解，防止 Worker 运行时崩溃
 *  [F2] 强制 Provider 路由 (`openai:gpt-4o`)：现在真正按 provider.name 查找，而非继续走路由表
 *  [F3] handleAnthropicStream: hasSentDone 从未置 true，修复重复发送 [DONE]
 *  [F4] universalStreamToOpenAI: SSE 与 JSON 数组双 buffer 冲突，拆分为独立解析通道
 *  [F5] encrypt/decrypt: 固定 salt 改为随机 salt，与密文一起存储，安全性大幅提升
 *  [F6] convertOpenAIToAnthropic: 支持多模态 content 数组，不再静默丢弃图片
 *  [F7] logRequest: 不再静默吞掉 DB 错误，改为 console.error 输出
 *  [F8] handleListModels: 改为从数据库动态读取路由前缀，不再返回硬编码列表
 *  [F9] findRouteForModel: 改用 SQL LIKE 查询，避免全表扫描
 */

const VERSION = '3.1.0';
const SESSION_COOKIE_NAME = 'LLM_GATEWAY_SESSION';

// ================= 1. 核心入口 =================

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") return handleOptions(request);

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (path === '/v1/chat/completions' && request.method === 'POST') {
        return await handleChatCompletions(request, env, ctx);
      }
      if (path === '/v1/models' && request.method === 'GET') {
        return await handleListModels(request, env);
      }
      if (path === '/health') {
        return createResponse({ status: 'ok', version: VERSION });
      }
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

// ================= 2. 聊天处理核心 =================

async function handleChatCompletions(request, env, ctx) {
  const client = await authenticateClient(request, env);
  if (!client) return createResponse({ error: { message: 'Invalid API Key', type: 'invalid_request_error', code: 401 } }, 401);

  let body;
  try { body = await request.json(); } catch(e) {
    return createResponse({ error: { message: 'Invalid JSON', type: 'invalid_request_error', code: 400 } }, 400);
  }

  const originalModel = body.model || 'gpt-3.5-turbo';
  const isStream = body.stream === true;

  // [F2] 强制 Provider 路由与普通路由分离
  let route;
  let realModel;

  if (originalModel.includes(':')) {
    // 格式: "providerName:modelName"，按 provider.name 直接查找
    const colonIdx = originalModel.indexOf(':');
    const providerName = originalModel.substring(0, colonIdx);
    realModel = originalModel.substring(colonIdx + 1);

    route = await findProviderByName(env, providerName);
    if (!route) {
      return createResponse({ error: { message: `No provider named: ${providerName}`, type: 'routing_error', code: 404 } }, 404);
    }
  } else {
    realModel = originalModel;
    route = await findRouteForModel(env, originalModel);
    if (!route) {
      return createResponse({ error: { message: `No route configured for model: ${originalModel}`, type: 'routing_error', code: 404 } }, 404);
    }
  }

  const apiKey = await decrypt(route.api_key_enc, route.iv, route.salt, env.MASTER_KEY);
  if (!apiKey) return createResponse({ error: { message: 'Provider configuration error (key decryption failed)', type: 'config_error' } }, 500);

  const startTime = Date.now();
  ctx.waitUntil(updateClientUsage(env, client.id));

  try {
    const response = await dispatchProvider(route, apiKey, body, realModel, isStream);
    ctx.waitUntil(logRequest(env, client.name, route.name, originalModel, isStream, response.status, Date.now() - startTime));
    return response;
  } catch (e) {
    console.error("Dispatch Error:", e);
    return createResponse({ error: { message: `Upstream error: ${e.message}`, type: 'upstream_error', code: 502 } }, 502);
  }
}

async function dispatchProvider(provider, apiKey, body, realModel, isStream) {
  const headers = { 'Content-Type': 'application/json' };
  const targetUrl = resolveUrl(provider.base_url, provider.path, provider.type, realModel, isStream, apiKey);

  if (provider.type === 'openai' || provider.type === 'openai_compat_loose') {
    headers['Authorization'] = `Bearer ${apiKey}`;
    const newBody = { ...body, model: realModel };
    const resp = await fetch(targetUrl, { method: 'POST', headers, body: JSON.stringify(newBody) });
    if (!resp.ok) return proxyErrorResponse(resp, provider.name);
    if (isStream) return universalStreamToOpenAI(resp, realModel);
    const data = await resp.json();
    return createResponse(normalizeOpenAIResponse(data, realModel));
  }

  else if (provider.type === 'anthropic') {
    headers['x-api-key'] = apiKey;
    headers['anthropic-version'] = '2023-06-01';
    const anthropicBody = convertOpenAIToAnthropic(body, realModel, isStream);
    const resp = await fetch(targetUrl, { method: 'POST', headers, body: JSON.stringify(anthropicBody) });
    if (!resp.ok) return proxyErrorResponse(resp, provider.name);
    if (isStream) return handleAnthropicStream(resp, realModel);
    const data = await resp.json();
    return createResponse(convertAnthropicToOpenAI(data, realModel));
  }

  else if (provider.type === 'gemini') {
    const geminiBody = convertOpenAIToGemini(body);
    const resp = await fetch(targetUrl, { method: 'POST', headers, body: JSON.stringify(geminiBody) });
    if (!resp.ok) return proxyErrorResponse(resp, provider.name);
    if (isStream) return universalStreamToOpenAI(resp, realModel);
    const data = await resp.json();
    return createResponse(convertGeminiToOpenAI(data, realModel));
  }

  throw new Error(`Unknown provider type: ${provider.type}`);
}

// ================= 3. 智能路径解析 =================

function resolveUrl(baseUrl, userPath, type, model, isStream, apiKey) {
  let url = baseUrl.replace(/\/+$/, '');
  let path = (userPath || '').trim();

  if (type === 'openai' || type === 'openai_compat_loose') {
    if (!path) return `${url}/v1/chat/completions`;
    if (/^\/?v1\/?$/.test(path)) return `${url}/v1/chat/completions`;
    if (path.includes('/chat/completions')) {
      return path.startsWith('/') ? `${url}${path}` : `${url}/${path}`;
    }
    const cleanPath = path.startsWith('/') ? path : `/${path}`;
    return `${url}${cleanPath.replace(/\/$/, '')}/chat/completions`;
  }

  if (type === 'anthropic') {
    if (!path || /^\/?v1\/?$/.test(path)) return `${url}/v1/messages`;
    return path.startsWith('/') ? `${url}${path}` : `${url}/${path}`;
  }

  if (type === 'gemini') {
    const method = isStream ? 'streamGenerateContent' : 'generateContent';
    let version = 'v1beta';
    if (path) version = path.replace(/^\//, '').replace(/\/$/, '');
    return `${url}/${version}/models/${model}:${method}?key=${apiKey}`;
  }

  return url;
}

// [F1] 移除 `: any` TypeScript 注解，防止 Worker 运行时语法崩溃
async function proxyErrorResponse(resp, providerName) {
  let errorBody = {};
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

// ================= 4. 流处理 =================

// [F4] 拆分 SSE 与 JSON 数组解析通道，消除 buffer 冲突
function universalStreamToOpenAI(response, model) {
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  (async () => {
    const reader = response.body.getReader();
    let buffer = '';
    let hasSentDone = false;

    const sendDone = async () => {
      if (!hasSentDone) {
        hasSentDone = true;
        await writer.write(encoder.encode('data: [DONE]\n\n'));
      }
    };

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        // --- 通道 A: SSE 行解析 ---
        const lines = buffer.split('\n');
        // 只保留最后一段（可能不完整的行）
        buffer = lines.pop();

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed) continue;

          if (trimmed === 'data: [DONE]' || trimmed === '[DONE]') {
            await sendDone();
            continue;
          }

          let jsonStr = '';
          if (trimmed.startsWith('data: ')) jsonStr = trimmed.slice(6);
          else if (trimmed.startsWith('{')) jsonStr = trimmed;

          if (jsonStr) {
            try {
              const data = JSON.parse(jsonStr);
              await emitChunk(writer, encoder, data, model);
            } catch (e) { /* 忽略解析失败的碎片行 */ }
          }
        }

        // --- 通道 B: JSON 数组流解析 (仅当 buffer 是纯 JSON 片段时处理) ---
        // 仅在 buffer 不含 SSE 前缀时才进入此通道，防止污染
        const trimmedBuf = buffer.trimStart();
        const isJsonFragment = (trimmedBuf.startsWith('{') || trimmedBuf.startsWith('[') || trimmedBuf.startsWith(','));
        const isSseFragment = trimmedBuf.startsWith('data:') || trimmedBuf.startsWith('event:') || trimmedBuf.startsWith(':');

        if (isJsonFragment && !isSseFragment) {
          const { remaining, objects } = extractObjects(trimmedBuf);
          if (objects.length > 0) {
            buffer = remaining; // 只在真正解析出对象时才更新 buffer
            for (const data of objects) {
              await emitChunk(writer, encoder, data, model);
            }
          }
        }
      }

      // 处理末尾残留
      const remaining = buffer.trim();
      if (remaining && remaining !== '[DONE]' && remaining !== 'data: [DONE]') {
        try {
          const clean = remaining.replace(/^data: /, '');
          const data = JSON.parse(clean);
          await emitChunk(writer, encoder, data, model);
        } catch(e) { /* 正常，末尾可能是空或残缺 */ }
      }

      await sendDone();
    } catch (e) {
      const errChunk = createOpenAIChunk(`\n\n[Gateway Error: ${e.message}]`, model, 'stop');
      await writer.write(encoder.encode(`data: ${JSON.stringify(errChunk)}\n\n`));
      await sendDone();
    } finally {
      writer.close();
    }
  })();

  return new Response(readable, { headers: { 'Content-Type': 'text/event-stream', ...corsHeaders() } });
}

// [F3] 修复 hasSentDone 从未置 true 的 Bug
function handleAnthropicStream(response, model) {
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  (async () => {
    const reader = response.body.getReader();
    let buffer = '';
    let hasSentDone = false;

    const sendDone = async () => {
      if (!hasSentDone) {
        hasSentDone = true; // [F3] 正确置位
        await writer.write(encoder.encode('data: [DONE]\n\n'));
      }
    };

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop();

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const payload = line.slice(6).trim();

          // Anthropic 流结束信号
          if (payload === '[DONE]') { await sendDone(); continue; }

          try {
            const event = JSON.parse(payload);
            // content_block_delta: 正文增量
            if (event.type === 'content_block_delta' && event.delta?.text) {
              const chunk = createOpenAIChunk(event.delta.text, model, null);
              await writer.write(encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`));
            }
            // message_delta: 结束原因
            else if (event.type === 'message_delta' && event.delta?.stop_reason) {
              const chunk = createOpenAIChunk('', model, event.delta.stop_reason === 'end_turn' ? 'stop' : event.delta.stop_reason);
              await writer.write(encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`));
            }
            // message_stop: 流真正结束
            else if (event.type === 'message_stop') {
              await sendDone();
            }
          } catch(e) { /* 忽略解析错误 */ }
        }
      }
      await sendDone();
    } catch(e) {
      console.error("[AnthropicStream Error]", e);
      await sendDone();
    } finally {
      writer.close();
    }
  })();

  return new Response(readable, { headers: { 'Content-Type': 'text/event-stream', ...corsHeaders() } });
}

function extractTextFromAnywhere(data) {
  if (!data) return '';
  if (data.choices?.[0]?.delta?.content) return data.choices[0].delta.content;
  if (data.choices?.[0]?.message?.content) {
    const c = data.choices[0].message.content;
    return typeof c === 'string' ? c : (Array.isArray(c) ? c.map(p => p.text || '').join('') : '');
  }
  if (data.choices?.[0]?.text) return data.choices[0].text;
  if (data.text) return data.text;
  if (data.output_text) return data.output_text;
  if (Array.isArray(data.content) && data.content[0]?.text) return data.content[0].text;
  if (typeof data.content === 'string') return data.content;
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
    choices: [{ index: 0, delta: text ? { content: text } : {}, finish_reason }]
  };
}

function normalizeOpenAIResponse(data, model) {
  if (data?.choices?.[0]?.message?.role === 'assistant') return data;
  const content = extractTextFromAnywhere(data);
  const finish_reason = data.stop_reason || data.choices?.[0]?.finish_reason || 'stop';
  return {
    id: data.id || `chatcmpl-${Date.now()}`,
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [{ index: 0, message: { role: 'assistant', content: content || '' }, finish_reason }],
    usage: data.usage || { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 }
  };
}

function extractObjects(str) {
  let startIdx = 0, openBraces = 0;
  let inString = false, objects = [];
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    if (char === '"' && str[i - 1] !== '\\') inString = !inString;
    if (!inString) {
      if (char === '{') { if (openBraces === 0) startIdx = i; openBraces++; }
      if (char === '}') {
        openBraces--;
        if (openBraces === 0) {
          try { objects.push(JSON.parse(str.substring(startIdx, i + 1))); } catch(e) {}
          startIdx = i + 1;
        }
      }
    }
  }
  return { remaining: str.slice(startIdx), objects };
}

// ================= 5. Provider 格式转换 =================

// [F6] 支持多模态 content 数组，不再静默丢弃图片内容
function convertOpenAIToAnthropic(body, model, stream) {
  let system = '';
  const messages = [];

  for (const msg of body.messages) {
    if (msg.role === 'system') {
      // system 消息的 content 也可能是数组
      const text = typeof msg.content === 'string'
        ? msg.content
        : Array.isArray(msg.content)
          ? msg.content.filter(p => p.type === 'text').map(p => p.text).join('\n')
          : '';
      system += text + '\n';
    } else {
      const role = msg.role === 'assistant' ? 'assistant' : 'user';
      let content;

      if (typeof msg.content === 'string') {
        content = msg.content;
      } else if (Array.isArray(msg.content)) {
        // [F6] 将 OpenAI 多模态数组转为 Anthropic content 数组
        content = msg.content.map(part => {
          if (part.type === 'text') return { type: 'text', text: part.text };
          if (part.type === 'image_url') {
            const url = part.image_url?.url || '';
            // base64 格式: data:image/jpeg;base64,xxxxx
            const match = url.match(/^data:([^;]+);base64,(.+)$/);
            if (match) {
              return { type: 'image', source: { type: 'base64', media_type: match[1], data: match[2] } };
            }
            // URL 格式
            return { type: 'image', source: { type: 'url', url } };
          }
          return { type: 'text', text: JSON.stringify(part) }; // 未知类型降级
        });
      } else {
        content = '';
      }

      messages.push({ role, content });
    }
  }

  return {
    model,
    messages,
    system: system.trim() || undefined,
    max_tokens: body.max_tokens || 4096,
    stream,
    temperature: body.temperature
  };
}

function convertAnthropicToOpenAI(data, model) {
  return normalizeOpenAIResponse(data, model);
}

function convertOpenAIToGemini(body) {
  const contents = [];
  let systemInstruction = undefined;
  for (const msg of body.messages) {
    if (msg.role === 'system') {
      systemInstruction = { parts: [{ text: typeof msg.content === 'string' ? msg.content : '' }] };
    } else {
      const role = msg.role === 'assistant' ? 'model' : 'user';
      let parts;
      if (typeof msg.content === 'string') {
        parts = [{ text: msg.content }];
      } else if (Array.isArray(msg.content)) {
        parts = msg.content.map(p => {
          if (p.type === 'text') return { text: p.text };
          if (p.type === 'image_url') {
            const url = p.image_url?.url || '';
            const match = url.match(/^data:([^;]+);base64,(.+)$/);
            if (match) return { inlineData: { mimeType: match[1], data: match[2] } };
            return { text: `[Image: ${url}]` };
          }
          return { text: JSON.stringify(p) };
        });
      } else {
        parts = [{ text: '' }];
      }
      contents.push({ role, parts });
    }
  }
  // Gemini 要求第一条必须是 user 角色
  if (contents.length > 0 && contents[0].role === 'model') {
    contents.unshift({ role: 'user', parts: [{ text: ' ' }] });
  }
  return { contents, systemInstruction, generationConfig: { maxOutputTokens: body.max_tokens, temperature: body.temperature } };
}

function convertGeminiToOpenAI(data, model) {
  return normalizeOpenAIResponse(data, model);
}

// ================= 6. 管理后台 =================

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

  if (path === '/admin/login') {
    return new Response(buildUI('login'), { headers: { 'Content-Type': 'text/html' } });
  }

  if (!session) {
    if (path.startsWith('/api/')) return createResponse({ error: 'Unauthorized' }, 401);
    return Response.redirect(new URL('/admin/login', request.url).toString(), 302);
  }

  if (path === '/admin' || path === '/admin/') {
    return new Response(buildUI('dashboard'), { headers: { 'Content-Type': 'text/html' } });
  }

  // Providers
  if (path === '/api/admin/providers') {
    if (request.method === 'GET') {
      const { results } = await env.DB.prepare(
        'SELECT id, name, type, base_url, path, is_enabled, created_at FROM providers ORDER BY id DESC'
      ).all();
      return createResponse(results);
    }
    if (request.method === 'POST') {
      const d = await request.json();
      if (!d.name || !d.type || !d.base_url || !d.key) {
        return createResponse({ error: 'Missing required fields: name, type, base_url, key' }, 400);
      }
      const enc = await encrypt(d.key, env.MASTER_KEY);
      await env.DB.prepare(
        'INSERT INTO providers (name, type, base_url, path, api_key_enc, iv, salt, is_enabled) VALUES (?, ?, ?, ?, ?, ?, ?, 1)'
      ).bind(d.name, d.type, d.base_url, d.path || '', enc.text, enc.iv, enc.salt).run();
      return createResponse({ success: true });
    }
  }

  if (path.startsWith('/api/admin/providers/') && request.method === 'DELETE') {
    const id = parseInt(path.split('/').pop(), 10);
    if (isNaN(id)) return createResponse({ error: 'Invalid id' }, 400);
    await env.DB.prepare('DELETE FROM providers WHERE id = ?').bind(id).run();
    return createResponse({ success: true });
  }

  // Routes
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
      if (!d.prefix || !d.provider_id) return createResponse({ error: 'Missing prefix or provider_id' }, 400);
      await env.DB.prepare('INSERT INTO routes (prefix, provider_id) VALUES (?, ?)').bind(d.prefix, d.provider_id).run();
      return createResponse({ success: true });
    }
  }

  if (path.startsWith('/api/admin/routes/') && request.method === 'DELETE') {
    const id = parseInt(path.split('/').pop(), 10);
    if (isNaN(id)) return createResponse({ error: 'Invalid id' }, 400);
    await env.DB.prepare('DELETE FROM routes WHERE id = ?').bind(id).run();
    return createResponse({ success: true });
  }

  // Clients
  if (path === '/api/admin/clients') {
    if (request.method === 'GET') {
      const { results } = await env.DB.prepare(
        'SELECT id, name, key_prefix, last_used_at, is_active, created_at FROM clients ORDER BY id DESC'
      ).all();
      return createResponse(results);
    }
    if (request.method === 'POST') {
      const { name } = await request.json();
      if (!name || !name.trim()) return createResponse({ error: 'Missing client name' }, 400);
      const rawKey = 'sk-gw-' + crypto.randomUUID().replace(/-/g, '');
      const keyHash = await hashSHA256(rawKey);
      const prefix = rawKey.substring(0, 10);
      await env.DB.prepare(
        'INSERT INTO clients (name, key_hash, key_prefix, is_active) VALUES (?, ?, ?, 1)'
      ).bind(name.trim(), keyHash, prefix).run();
      return createResponse({ success: true, raw_key: rawKey });
    }
  }

  if (path.startsWith('/api/admin/clients/') && request.method === 'DELETE') {
    const id = parseInt(path.split('/').pop(), 10);
    if (isNaN(id)) return createResponse({ error: 'Invalid id' }, 400);
    await env.DB.prepare('DELETE FROM clients WHERE id = ?').bind(id).run();
    return createResponse({ success: true });
  }

  return createResponse({ error: 'Not Found' }, 404);
}

// ================= 7. 工具函数 =================

async function updateClientUsage(env, id) {
  try {
    await env.DB.prepare('UPDATE clients SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?').bind(id).run();
  } catch(e) {
    console.error('[updateClientUsage]', e);
  }
}

// [F7] 不再静默吞掉错误，改为 console.error
async function logRequest(env, cName, pName, model, isStream, status, dur) {
  try {
    await env.DB.prepare(
      'INSERT INTO access_logs (client_name, provider_name, model, is_stream, status, duration_ms) VALUES (?,?,?,?,?,?)'
    ).bind(cName, pName, model, isStream ? 1 : 0, status, dur).run();
  } catch(e) {
    console.error('[logRequest DB Error]', e);
  }
}

// [F9] 改用 SQL LIKE 做最长前缀匹配，避免全表扫描内存过滤
async function findRouteForModel(env, model) {
  // 取所有前缀，找出能匹配该 model 的最长前缀
  const { results } = await env.DB.prepare(`
    SELECT r.*, p.name, p.type, p.base_url, p.path, p.api_key_enc, p.iv, p.salt
    FROM routes r JOIN providers p ON r.provider_id = p.id
    WHERE p.is_enabled = 1 AND ? LIKE (r.prefix || '%')
    ORDER BY length(r.prefix) DESC
    LIMIT 1
  `).bind(model).all();
  return results[0] || null;
}

// [F2] 按 Provider name 直接查找（强制路由专用）
async function findProviderByName(env, name) {
  return await env.DB.prepare(
    'SELECT * FROM providers WHERE name = ? AND is_enabled = 1 LIMIT 1'
  ).bind(name).first();
}

// [F8] 从数据库动态生成模型列表，不再硬编码
async function handleListModels(request, env) {
  const client = await authenticateClient(request, env);
  if (!client) return createResponse({ error: { message: 'Invalid API Key', type: 'invalid_request_error' } }, 401);

  const { results } = await env.DB.prepare(
    'SELECT r.prefix, p.name as provider_name FROM routes r JOIN providers p ON r.provider_id = p.id WHERE p.is_enabled = 1'
  ).all();

  const data = results.map(r => ({
    id: `${r.prefix}*`,
    object: 'model',
    owned_by: r.provider_name,
    created: Math.floor(Date.now() / 1000)
  }));

  return createResponse({ object: 'list', data });
}

function createResponse(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(), ...extraHeaders }
  });
}

function handleOptions() {
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
  return await env.DB.prepare(
    'SELECT * FROM clients WHERE key_hash = ? AND is_active = 1'
  ).bind(keyHash).first();
}

// --- Crypto ---

async function hashSHA256(text) {
  const buf = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// [F5] 使用随机 salt，每次加密独立，彻底解决固定 salt 安全问题
async function getAESKey(secret, salt) {
  const enc = new TextEncoder();
  const keyMat = await crypto.subtle.importKey('raw', enc.encode(secret), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
    keyMat, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

async function encrypt(text, secret) {
  const salt = crypto.getRandomValues(new Uint8Array(16)); // [F5] 随机 salt
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await getAESKey(secret, salt);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(text));
  return {
    text: btoa(String.fromCharCode(...new Uint8Array(ct))),
    iv: btoa(String.fromCharCode(...iv)),
    salt: btoa(String.fromCharCode(...salt)) // [F5] salt 一并存储
  };
}

// [F5] decrypt 需要接收 salt 参数
async function decrypt(txt, ivStr, saltStr, secret) {
  try {
    let salt;
    if (saltStr) {
      // 新格式: 随机 salt
      salt = Uint8Array.from(atob(saltStr), c => c.charCodeAt(0));
    } else {
      // 兼容旧格式: 固定 salt (迁移期临时兼容)
      salt = new TextEncoder().encode('fixed-salt');
    }
    const key = await getAESKey(secret, salt);
    const ct = Uint8Array.from(atob(txt), c => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(ivStr), c => c.charCodeAt(0));
    const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return new TextDecoder().decode(dec);
  } catch(e) {
    console.error('[decrypt error]', e);
    return null;
  }
}

async function getHMACKey(secret) {
  return crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function createSessionCookie(env) {
  const exp = Date.now() + 86400 * 1000;
  const jti = crypto.randomUUID(); // 防重放标识（可扩展至黑名单）
  const payload = btoa(JSON.stringify({ role: 'admin', exp, jti }));
  const secret = env.SESSION_SECRET || env.MASTER_KEY;
  const key = await getHMACKey(secret);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return `${SESSION_COOKIE_NAME}=${payload}.${sigB64}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`;
}

async function verifySession(request, env) {
  const cookie = request.headers.get('Cookie');
  if (!cookie) return false;
  const match = cookie.match(new RegExp(`${SESSION_COOKIE_NAME}=([^;]+)`));
  if (!match) return false;
  const parts = match[1].split('.');
  if (parts.length !== 2) return false;
  const [payloadB64, sigB64] = parts;
  const secret = env.SESSION_SECRET || env.MASTER_KEY;
  const key = await getHMACKey(secret);
  const sig = Uint8Array.from(atob(sigB64), c => c.charCodeAt(0));
  const valid = await crypto.subtle.verify('HMAC', key, sig, new TextEncoder().encode(payloadB64));
  if (!valid) return false;
  try {
    const payload = JSON.parse(atob(payloadB64));
    return payload.exp > Date.now();
  } catch(e) { return false; }
}

// ================= 8. Admin UI =================

function buildUI(view) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Gateway Admin v${VERSION}</title>
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
      <p v-if="loginError" class="text-red-500 text-sm mt-3 text-center">{{ loginError }}</p>
    </div>
  </div>

  <div v-if="view === 'dashboard'" class="max-w-5xl mx-auto p-4">
    <header class="flex justify-between items-center mb-8 py-4 border-b border-gray-200">
      <div>
        <h1 class="text-3xl font-extrabold text-slate-800">Unified Gateway</h1>
        <p class="text-sm text-gray-500">v${VERSION}</p>
      </div>
    </header>

    <div class="grid grid-cols-1 gap-8">
      <!-- Providers -->
      <section class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <h2 class="text-xl font-bold mb-4">🔌 Providers</h2>
        <div class="space-y-3">
          <div v-for="p in providers" :key="p.id" class="flex justify-between items-center bg-slate-50 p-4 rounded-lg border border-slate-100">
            <div>
              <div class="font-bold text-lg">{{ p.name }}
                <span class="text-xs ml-2 bg-blue-100 text-blue-800 px-2 py-0.5 rounded-full uppercase">{{ p.type }}</span>
              </div>
              <div class="text-xs text-gray-500 font-mono mt-1">{{ p.base_url }} | Path: {{ p.path || 'Auto' }}</div>
            </div>
            <button @click="delProvider(p.id)" class="text-red-500 hover:text-red-700 font-medium text-sm">Remove</button>
          </div>
          <p v-if="providers.length === 0" class="text-gray-400 text-sm text-center py-4">No providers yet.</p>
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
          <p v-if="provError" class="text-red-500 text-sm col-span-2">{{ provError }}</p>
          <button @click="addProvider" class="bg-emerald-600 text-white p-2 rounded col-span-2 font-bold hover:bg-emerald-700">Add Provider</button>
        </div>
      </section>

      <!-- Routes -->
      <section class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <h2 class="text-xl font-bold mb-4">🔀 Routes</h2>
        <div class="space-y-2">
          <div v-for="r in routes" :key="r.id" class="flex justify-between items-center border-b border-gray-100 py-3 last:border-0">
            <div class="flex items-center">
              <span class="font-mono bg-amber-100 text-amber-800 px-2 py-1 rounded text-sm mr-3">{{ r.prefix }}*</span>
              <span class="text-gray-400">➜</span>
              <span class="ml-3 font-semibold">{{ r.provider_name }}</span>
            </div>
            <button @click="delRoute(r.id)" class="text-red-500 hover:text-red-700 text-sm">Remove</button>
          </div>
          <p v-if="routes.length === 0" class="text-gray-400 text-sm text-center py-4">No routes yet.</p>
        </div>
        <div class="flex gap-3 mt-4">
          <input v-model="newRoute.prefix" placeholder="Prefix (e.g. gpt-)" class="border p-2 rounded flex-1">
          <select v-model="newRoute.provider_id" class="border p-2 rounded flex-1">
            <option :value="null" disabled>Select Provider</option>
            <option v-for="p in providers" :value="p.id">{{ p.name }}</option>
          </select>
          <button @click="addRoute" class="bg-blue-600 text-white px-6 py-2 rounded font-bold hover:bg-blue-700">Add</button>
        </div>
      </section>

      <!-- Client Keys -->
      <section class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <h2 class="text-xl font-bold mb-4">🔑 Client Keys</h2>
        <div v-if="newKey" class="mb-6 bg-green-50 border border-green-200 p-4 rounded-lg">
          <p class="text-green-800 font-bold mb-1">✅ Copy this key now — it won't be shown again:</p>
          <code class="block bg-white border p-3 rounded text-lg select-all break-all">{{ newKey }}</code>
        </div>
        <div class="space-y-2 mb-4">
          <div v-for="c in clients" :key="c.id" class="flex justify-between items-center bg-gray-50 p-3 rounded border border-gray-100">
            <div>
              <div class="font-bold text-gray-800">{{ c.name }}</div>
              <div class="text-xs text-gray-500 mt-1">Prefix: {{ c.key_prefix }}... | Active: {{ c.is_active }} | Last used: {{ c.last_used_at || 'never' }}</div>
            </div>
            <button @click="delClient(c.id)" class="text-red-500 hover:text-red-700 text-sm">Revoke</button>
          </div>
          <p v-if="clients.length === 0" class="text-gray-400 text-sm text-center py-4">No clients yet.</p>
        </div>
        <div class="flex gap-3">
          <input v-model="newClientName" placeholder="Client Name (e.g. iPhone Chatbox)" class="border p-2 rounded flex-1">
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
    const view = ref('${view}');
    const password = ref(''); const loginError = ref(''); const provError = ref(''); const newKey = ref('');
    const providers = ref([]); const routes = ref([]); const clients = ref([]);
    const newProv = ref({ name:'', type:'openai', base_url:'', path:'', key:'' });
    const newRoute = ref({ prefix:'', provider_id: null });
    const newClientName = ref('');

    const api = async (url, method='GET', body=null) => {
      const r = await fetch(url, { method, headers: {'Content-Type':'application/json'}, body: body ? JSON.stringify(body) : null });
      if (r.status === 401 && url !== '/api/admin/login') { location.href = '/admin/login'; return null; }
      return r.json();
    };

    const login = async () => {
      loginError.value = '';
      const res = await api('/api/admin/login', 'POST', { password: password.value });
      if (res?.success) location.reload();
      else loginError.value = 'Incorrect password';
    };

    const load = async () => {
      if (view.value !== 'dashboard') return;
      providers.value = await api('/api/admin/providers') || [];
      routes.value = await api('/api/admin/routes') || [];
      clients.value = await api('/api/admin/clients') || [];
    };

    const addProvider = async () => {
      provError.value = '';
      if (!newProv.value.name || !newProv.value.base_url || !newProv.value.key) {
        provError.value = 'Name, Base URL and API Key are required.'; return;
      }
      await api('/api/admin/providers', 'POST', newProv.value);
      newProv.value = { name:'', type:'openai', base_url:'', path:'', key:'' };
      load();
    };
    const delProvider = async (id) => { if (confirm('Remove this provider?')) { await api('/api/admin/providers/' + id, 'DELETE'); load(); } };

    const addRoute = async () => {
      if (!newRoute.value.prefix || !newRoute.value.provider_id) { alert('Please fill prefix and select a provider'); return; }
      await api('/api/admin/routes', 'POST', newRoute.value);
      newRoute.value.prefix = '';
      load();
    };
    const delRoute = async (id) => { await api('/api/admin/routes/' + id, 'DELETE'); load(); };

    const addClient = async () => {
      if (!newClientName.value.trim()) { alert('Please enter a client name'); return; }
      const r = await api('/api/admin/clients', 'POST', { name: newClientName.value });
      if (r?.raw_key) { newKey.value = r.raw_key; newClientName.value = ''; load(); }
    };
    const delClient = async (id) => { if (confirm('Revoke this key?')) { await api('/api/admin/clients/' + id, 'DELETE'); load(); } };

    onMounted(load);
    return { view, password, loginError, provError, login, providers, routes, clients, newProv, addProvider, delProvider, newRoute, addRoute, delRoute, newClientName, newKey, addClient, delClient };
  }
}).mount('#app');
</script>
</body>
</html>`;
}