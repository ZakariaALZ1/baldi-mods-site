import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

serve(async (req) => {
  try {
    // Verify cron secret (optional but recommended)
    const authHeader = req.headers.get('authorization');
    if (authHeader !== `Bearer ${Deno.env.get('CRON_SECRET')}`) {
      return new Response('Unauthorized', { status: 401 });
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    const { data: local, error } = await supabase
      .from("threat_signatures")
      .select("*");

    if (error) throw error;

    let synced = 0;
    for (const s of local || []) {
      const { error: upsertError } = await supabase
        .from("threat_feed")
        .upsert({
          signature: s.pattern || s.hash,
          risk: s.weight || 50,
          source: "local",
          metadata: s,
          updated_at: new Date().toISOString()
        }, {
          onConflict: 'signature'
        });
      
      if (!upsertError) synced++;
    }

    return new Response(
      JSON.stringify({ 
        message: "feed synced", 
        synced,
        total: local?.length || 0 
      }),
      { 
        status: 200, 
        headers: { 'Content-Type': 'application/json' } 
      }
    );

  } catch (error) {
    return new Response(
      JSON.stringify({ error: error.message }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
});