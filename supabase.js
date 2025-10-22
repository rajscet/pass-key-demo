import { createClient } from '@supabase/supabase-js';
const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = process.env;

export const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
});

export async function ensureProfile({ userId, phone }) {
  const { data: byId } = await supabase.from('profiles').select('*').eq('id', userId).maybeSingle();
  if (byId) return byId;

  const { data: inserted, error } = await supabase
    .from('profiles')
    .insert({ id: userId, phone })
    .select('*')
    .single();

  if (!error) return inserted;

  if (error && error.code === '23505') {
    const { data: byPhone } = await supabase.from('profiles').select('*').eq('phone', phone).maybeSingle();
    if (byPhone) return byPhone;
  }
  throw error;
}
