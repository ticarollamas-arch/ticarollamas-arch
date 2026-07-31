import React, { useEffect, useState } from 'react';
import { Calendar } from 'lucide-react';

interface PostSummary {
  slug: string;
  title: string;
  meta_description: string;
  image_url: string | null;
  created_at: string;
}

interface PostFull extends PostSummary {
  body_html: string;
}

export const BlogPage = () => {
  const [posts, setPosts] = useState<PostSummary[] | null>(null);
  const [openSlug, setOpenSlug] = useState<string | null>(null);
  const [openPost, setOpenPost] = useState<PostFull | null>(null);

  useEffect(() => {
    fetch('/api/blog')
      .then((r) => r.json())
      .then(setPosts)
      .catch(() => setPosts([]));
  }, []);

  useEffect(() => {
    if (!openSlug) return;
    fetch(`/api/blog/${openSlug}`)
      .then((r) => r.json())
      .then(setOpenPost)
      .catch(() => setOpenPost(null));
  }, [openSlug]);

  if (openSlug && openPost) {
    return (
      <div className="max-w-2xl mx-auto py-8 px-4">
        <button onClick={() => { setOpenSlug(null); setOpenPost(null); }} className="text-xs font-mono text-zinc-500 hover:text-zinc-300 mb-6">
          ← voltar
        </button>
        {openPost.image_url && (
          <img src={openPost.image_url} alt={openPost.title} className="w-full rounded-lg mb-6" />
        )}
        <h1 className="text-2xl font-bold text-zinc-100 mb-2">{openPost.title}</h1>
        <p className="text-zinc-500 text-sm mb-6">{openPost.meta_description}</p>
        <div className="prose prose-invert text-zinc-300" dangerouslySetInnerHTML={{ __html: openPost.body_html }} />
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto py-8 px-4">
      <h1 className="text-xl font-mono uppercase tracking-widest text-zinc-300 mb-6">Blog</h1>
      {posts === null && <p className="text-zinc-600 text-sm">Carregando...</p>}
      {posts?.length === 0 && <p className="text-zinc-600 text-sm">Nenhum artigo publicado ainda.</p>}
      <div className="flex flex-col gap-4">
        {posts?.map((p) => (
          <button
            key={p.slug}
            onClick={() => setOpenSlug(p.slug)}
            className="text-left border border-zinc-800 rounded-lg p-4 hover:border-zinc-600 transition-colors flex gap-4"
          >
            {p.image_url && <img src={p.image_url} alt="" className="w-16 h-16 rounded object-cover shrink-0" />}
            <div className="min-w-0">
              <h2 className="text-zinc-100 font-semibold truncate">{p.title}</h2>
              <p className="text-zinc-500 text-sm line-clamp-2">{p.meta_description}</p>
              <p className="text-zinc-600 text-xs flex items-center gap-1 mt-1">
                <Calendar size={10} /> {p.created_at?.slice(0, 10)}
              </p>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
};
