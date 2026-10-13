/**
 * Turns the original wedding photos into the encrypted web gallery under p/.
 *
 *   WEDDING_PW=... node tools/build.mjs "<folder of originals>"
 *
 * Every photo is resized twice (a full-screen copy and a grid thumbnail),
 * stripped of EXIF (GPS included), and encrypted with AES-256-GCM under a key
 * derived from the password with PBKDF2. Only ciphertext is committed, so the
 * repo can be public: without the password the files are noise. The page on
 * thenetsuiteguy.com derives the same key in the browser and decrypts.
 *
 * Output:
 *   p/meta.json      salt, iteration count, photo count, password check
 *   p/m.bin          encrypted manifest: [[width, height], ...] per photo
 *   p/t/0000.bin     encrypted thumbnail (webp)
 *   p/f/0000.bin     encrypted full-size copy (webp)
 * Each .bin is a 12-byte IV followed by the GCM ciphertext and tag.
 *
 * Re-running reuses the salt in p/meta.json and skips photos already built, so
 * it resumes after an interruption. It refuses to run with a different
 * password than the existing output was built with.
 */
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { webcrypto as crypto } from "node:crypto";
import { fileURLToPath } from "node:url";
import sharp from "sharp";

const FULL_EDGE = 2048;
const THUMB_EDGE = 480;
const ITERATIONS = 600000;

const src = process.argv[2];
const password = process.env.WEDDING_PW;
if (!src || !password) {
  console.error('usage: WEDDING_PW=... node tools/build.mjs "<folder of originals>"');
  process.exit(1);
}

const out = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "p");
fs.mkdirSync(path.join(out, "t"), { recursive: true });
fs.mkdirSync(path.join(out, "f"), { recursive: true });

const b64 = (buf) => Buffer.from(buf).toString("base64");
const CHECK = new TextEncoder().encode("wedding-photos");

async function deriveKey(salt, iterations) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function seal(key, data) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data));
  const blob = new Uint8Array(12 + ct.length);
  blob.set(iv);
  blob.set(ct, 12);
  return blob;
}

async function open(key, blob) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: blob.slice(0, 12) }, key, blob.slice(12)));
}

// Reuse the existing salt so already-built photos stay valid.
const metaPath = path.join(out, "meta.json");
let meta = fs.existsSync(metaPath) ? JSON.parse(fs.readFileSync(metaPath, "utf8")) : null;
const salt = meta ? Buffer.from(meta.salt, "base64") : crypto.getRandomValues(new Uint8Array(16));
const iterations = meta ? meta.iterations : ITERATIONS;
const key = await deriveKey(salt, iterations);
if (meta) {
  try {
    await open(key, Buffer.from(meta.check, "base64"));
  } catch {
    console.error("WEDDING_PW does not match the password p/ was built with. Delete p/ to start over.");
    process.exit(1);
  }
}

const files = fs
  .readdirSync(src)
  .filter((f) => /\.jpe?g$/i.test(f))
  .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
console.log(`${files.length} photos in ${src}`);

const dims = new Array(files.length);
const dimsPath = path.join(out, ".dims.json"); // plaintext cache, gitignored
const cachedDims = fs.existsSync(dimsPath) ? JSON.parse(fs.readFileSync(dimsPath, "utf8")) : {};

async function build(i) {
  const id = String(i).padStart(4, "0");
  const fullOut = path.join(out, "f", `${id}.bin`);
  const thumbOut = path.join(out, "t", `${id}.bin`);
  const cacheKey = files[i];
  if (cachedDims[cacheKey] && fs.existsSync(fullOut) && fs.existsSync(thumbOut)) {
    dims[i] = cachedDims[cacheKey];
    return false;
  }
  // .rotate() applies the EXIF orientation; sharp drops all metadata on output.
  const input = fs.readFileSync(path.join(src, files[i]));
  const full = await sharp(input)
    .rotate()
    .resize(FULL_EDGE, FULL_EDGE, { fit: "inside", withoutEnlargement: true })
    .webp({ quality: 80 })
    .toBuffer({ resolveWithObject: true });
  const thumb = await sharp(full.data)
    .resize(THUMB_EDGE, THUMB_EDGE, { fit: "inside" })
    .webp({ quality: 70 })
    .toBuffer();
  fs.writeFileSync(fullOut, await seal(key, full.data));
  fs.writeFileSync(thumbOut, await seal(key, thumb));
  dims[i] = cachedDims[cacheKey] = [full.info.width, full.info.height];
  return true;
}

let next = 0;
let done = 0;
let built = 0;
const started = Date.now();
async function worker() {
  while (next < files.length) {
    const i = next++;
    if (await build(i)) built++;
    if (++done % 25 === 0 || done === files.length) {
      fs.writeFileSync(dimsPath, JSON.stringify(cachedDims));
      const secs = Math.round((Date.now() - started) / 1000);
      console.log(`${done}/${files.length} (${built} built, ${secs}s)`);
    }
  }
}
sharp.concurrency(1);
await Promise.all(Array.from({ length: Math.max(1, os.cpus().length - 1) }, worker));

fs.writeFileSync(path.join(out, "m.bin"), await seal(key, new TextEncoder().encode(JSON.stringify(dims))));
meta = {
  v: 1,
  salt: b64(salt),
  iterations,
  count: files.length,
  check: meta ? meta.check : b64(await seal(key, CHECK)),
};
fs.writeFileSync(metaPath, JSON.stringify(meta, null, 2) + "\n");
console.log("done");
