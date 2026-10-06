import { createClient } from '@supabase/supabase-js';

function serverConfig() {
  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;

  if (typeof url !== 'string' || typeof secretKey !== 'string'
      || !url.trim() || !secretKey.trim()) {
    return null;
  }

  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:') return null;
  } catch {
    return null;
  }

  return { url: url.trim(), secretKey: secretKey.trim() };
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');

  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'method_not_allowed' });
  }

  const config = serverConfig();
  if (!config) {
    return response.status(500).json({ error: 'server_not_configured' });
  }

  const supabase = createClient(config.url, config.secretKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false,
    },
  });

  const { data, error } = await supabase
    .from('notes')
    .select('title,content')
    .order('id', { ascending: true });

  if (error) {
    return response.status(500).json({ error: 'notes_unavailable' });
  }

  return response.status(200).json({ notes: Array.isArray(data) ? data : [] });
}
