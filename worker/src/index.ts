export interface Env {
  SUBSTORE: KVNamespace;
  SUB_ACCESS_KEY: string;
  UPLOAD_TOKEN: string;
}

const FILE_KEYS: Record<string, string> = {
  "clash.yaml": "clash.yaml",
  "sub.base64": "sub.base64",
};

const MAX_UPLOAD_BYTES = 1024 * 1024;

function notFound(): Response {
  // 统一的 404，不区分"密钥错误"与"文件不存在"，避免探测
  return new Response("Not Found", { status: 404 });
}

async function handleRead(key: string, filename: string, env: Env): Promise<Response> {
  if (key !== env.SUB_ACCESS_KEY) return notFound();
  const stored = FILE_KEYS[filename];
  if (!stored) return notFound();
  const content = await env.SUBSTORE.get(stored);
  if (content === null) return notFound();
  const contentType =
    filename === "clash.yaml" ? "text/yaml; charset=utf-8" : "text/plain; charset=utf-8";
  return new Response(content, {
    headers: {
      "Content-Type": contentType,
      "Cache-Control": "no-store",
      "Profile-Update-Interval": "24",
      "Content-Disposition": `attachment; filename="${filename}"`,
    },
  });
}

async function handleUpload(
  request: Request,
  key: string,
  filename: string,
  env: Env,
): Promise<Response> {
  const auth = request.headers.get("Authorization") ?? "";
  if (auth !== `Bearer ${env.UPLOAD_TOKEN}`) return new Response("Forbidden", { status: 403 });
  if (key !== env.SUB_ACCESS_KEY) return new Response("Forbidden", { status: 403 });
  const stored = FILE_KEYS[filename];
  if (!stored) return new Response("Bad Request", { status: 400 });

  // 先看声明长度，避免把超大请求体整个读进内存（isolate 内存有限）
  const declared = Number(request.headers.get("Content-Length") ?? "0");
  if (Number.isFinite(declared) && declared > MAX_UPLOAD_BYTES) {
    return new Response("Payload Too Large", { status: 413 });
  }
  const body = await request.text();
  if (new TextEncoder().encode(body).length > MAX_UPLOAD_BYTES) {
    return new Response("Payload Too Large", { status: 413 });
  }
  await env.SUBSTORE.put(stored, body);
  return new Response("OK", { status: 200 });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts.length !== 3) return notFound();

    const [route, key, filename] = parts;
    if (route === "sub" && request.method === "GET") {
      return handleRead(key, filename, env);
    }
    if (route === "upload" && request.method === "PUT") {
      return handleUpload(request, key, filename, env);
    }
    return notFound();
  },
};
