import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

serve(async (req) => {
  try {
    // CORS headers
    if (req.method === 'OPTIONS') {
      return new Response('ok', { headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST',
        'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
      }});
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    const { mod_id } = await req.json();
    
    if (!mod_id) {
      return new Response(
        JSON.stringify({ error: "mod_id required" }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }

    const { data: events, error } = await supabase
      .from("telemetry_events")
      .select("*")
      .eq("mod_id", mod_id);

    if (error) throw error;

    let score = 0;
    for (const e of events || []) {
      score += e.risk_delta || 0;
    }

    await supabase
      .from("runtime_scores")
      .upsert({
        mod_id,
        score,
        last_update: new Date().toISOString()
      });

    return new Response(
      JSON.stringify({ correlated_score: score }),
      { 
        status: 200, 
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        } 
      }
    );

  } catch (error) {
    return new Response(
      JSON.stringify({ error: error.message }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
});