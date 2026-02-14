import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

interface ScanResult {
  safe: boolean;
  fingerprint: string;
  zero_trust_score: number;
  cluster: string;
  reason?: string;
  threats?: string[];
}

// CORS headers for all responses
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

serve(async (req: Request) => {
  // Handle preflight OPTIONS request
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders });
  }

  try {
    // Parse multipart form data
    const formData = await req.formData();
    const file = formData.get('file') as File;
    const title = formData.get('title') as string;
    const description = formData.get('description') as string;

    if (!file) {
      return new Response(
        JSON.stringify({ safe: false, reason: "No file provided" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Read file buffer
    const buffer = await file.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    
    // Calculate SHA-256 hash
    const hashBuffer = await crypto.subtle.digest("SHA-256", bytes);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const fingerprint = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");

    // Convert file content to text for scanning (first 1MB)
    const textDecoder = new TextDecoder("utf-8");
    const sampleSize = Math.min(bytes.length, 1024 * 1024);
    const fileSample = textDecoder.decode(bytes.slice(0, sampleSize));
    const fullText = `${title} ${description}`.toLowerCase();

    // ========== THREAT DETECTION ==========
    const threats: string[] = [];
    let riskScore = 0;

    // 1. Known malware keywords
    const malwareKeywords = [
      "hack", "crack", "keygen", "cheat engine",
      "token grabber", "password stealer"
      , "remote access", "backdoor",
      "injector", "dll inject", "process inject",
      "miner", "cryptominer", "bitcoin miner"
    ];

    for (const keyword of malwareKeywords) {
      if (fullText.includes(keyword) || fileSample.toLowerCase().includes(keyword)) {
        threats.push(`Malware keyword: ${keyword}`);
        riskScore += 25;
      }
    }

    // 2. System modification detection
    const systemKeywords = [
      "powershell", "cmd.exe", "command prompt",
      "regedit", "registry", "startup folder",
      "autorun", "system32", "windows\\system",
      "wscript", "cscript", "mshta"
      , "vbe", "jse"
    ];

    for (const keyword of systemKeywords) {
      if (fileSample.toLowerCase().includes(keyword)) {
        threats.push(`System modification: ${keyword}`);
        riskScore += 15;
      }
    }

    // 3. File type validation
    const fileExt = '.' + file.name.split('.').pop()?.toLowerCase();
    const allowedExtensions = ['.zip', '.rar', '.7z', '.baldimod'];
    
    if (!allowedExtensions.includes(fileExt)) {
      threats.push(`Invalid file type: ${fileExt}`);
      riskScore += 40;
    }

    // 4. Check file signature (magic bytes)
    const zipSignature = [0x50, 0x4B, 0x03, 0x04];
    const rarSignature = [0x52, 0x61, 0x72, 0x21];
    const sevenZipSignature = [0x37, 0x7A, 0xBC, 0xAF];
    
    let validSignature = false;
    if (bytes.length >= 4) {
      const header = Array.from(bytes.slice(0, 4));
      validSignature = 
        header.every((b, i) => b === zipSignature[i]) ||
        header.every((b, i) => b === rarSignature[i]) ||
        header.every((b, i) => b === sevenZipSignature[i]);
    }

    if (!validSignature && fileExt !== '.baldimod') {
      threats.push("Invalid file signature");
      riskScore += 30;
    }

    // 5. Suspicious patterns
    if (fileSample.includes("eval(")) {
      threats.push("Dynamic code evaluation");
      riskScore += 20;
    }

    if (fileSample.includes("base64_decode")) {
      threats.push("Base64 encoded content");
      riskScore += 15;
    }

    if (fileSample.includes("http://") || fileSample.includes("https://")) {
      const urlMatches = fileSample.match(/https?:\/\/[^\s"']+/g) || [];
      if (urlMatches.length > 3) {
        threats.push("Multiple external URLs");
        riskScore += 10;
      }
    }

    // 6. Check file size (now 2GB limit – optional, can be handled client-side)
    // if (file.size > 100 * 1024 * 1024) { ... } // optional

    // ========== RISK ASSESSMENT ==========
    const zeroTrustScore = Math.max(0, 100 - riskScore);
    const isSafe = zeroTrustScore >= 60 && threats.length === 0;

    // ========== THREAT CLUSTERING ==========
    let cluster = "clean";
    if (threats.some(t => t.includes("Malware"))) cluster = "malware";
    else if (threats.some(t => t.includes("System"))) cluster = "system-modifier";
    else if (threats.some(t => t.includes("Invalid file"))) cluster = "invalid-format";
    else if (riskScore > 50) cluster = "suspicious";

    // Store threat signature if malicious (optional, using service role key)
    if (!isSafe) {
      const supabase = createClient(
        Deno.env.get("SUPABASE_URL")!,
        Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
      );

      await supabase.from("threat_signatures").upsert({
        hash: fingerprint,
        pattern: file.name,
        weight: riskScore,
        source: "scan-mod",
        metadata: { threats, cluster }
      }, { onConflict: "hash" });
    }

    const result: ScanResult = {
      safe: isSafe,
      fingerprint,
      zero_trust_score: zeroTrustScore,
      cluster,
      reason: threats.length > 0 ? threats.join(", ") : undefined,
      threats
    };

    return new Response(
      JSON.stringify(result),
      { 
        status: 200, 
        headers: { 
          ...corsHeaders,
          "Content-Type": "application/json",
          "Cache-Control": "no-store"
        } 
      }
    );

  } catch (error) {
    console.error("Scan error:", error);
    
    return new Response(
      JSON.stringify({ 
        safe: false, 
        reason: "Scan failed",
        error: error.message 
      }),
      { 
        status: 500, 
        headers: { 
          ...corsHeaders,
          "Content-Type": "application/json" 
        } 
      }
    );
  }
});