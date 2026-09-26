import { pipeline } from "@huggingface/transformers";

type Extractor = (input:string|string[], options?:Record<string,unknown>) => Promise<{tolist:()=>unknown}>;

const MODEL = "Xenova/all-MiniLM-L6-v2";
let extractorPromise: Promise<Extractor> | null = null;

async function getExtractor(): Promise<FeatureExtractionPipeline> {
  if (!extractorPromise) {
    extractorPromise = pipeline("feature-extraction", MODEL) as unknown as Promise<Extractor>;
  }
  return extractorPromise;
}

function cosine(a: Float32Array, b: Float32Array): number {
  let dot = 0;
  let na = 0;
  let nb = 0;
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  return na && nb ? dot / (Math.sqrt(na) * Math.sqrt(nb)) : 0;
}

type EmbeddingCache = Record<string, number[]>;

const CACHE_KEY = "ra-xsoc-x-semantic-v1";

function readCache(): EmbeddingCache {
  try { return JSON.parse(localStorage.getItem(CACHE_KEY) || "{}") as EmbeddingCache; }
  catch { return {}; }
}

function writeCache(cache: EmbeddingCache): void {
  try { localStorage.setItem(CACHE_KEY, JSON.stringify(cache)); } catch { /* cache is optional */ }
}

export async function semanticRank(
  query: string,
  documents: Array<{ id: string; text: string }>,
): Promise<Map<string, number>> {
  const extractor = await getExtractor();
  const cache = readCache();
  const missing = documents.filter(d => !cache[d.id]);
  if (missing.length) {
    const output = await extractor(missing.map(d => d.text), { pooling: "mean", normalize: true });
    const rows = output.tolist() as number[][];
    missing.forEach((d, i) => { cache[d.id] = rows[i]; });
    writeCache(cache);
  }
  const q = await extractor(query, { pooling: "mean", normalize: true });
  const qv = Float32Array.from(q.tolist() as number[]);
  const result = new Map<string, number>();
  for (const d of documents) result.set(d.id, cosine(qv, Float32Array.from(cache[d.id])));
  return result;
}

export const semanticModel = MODEL;
