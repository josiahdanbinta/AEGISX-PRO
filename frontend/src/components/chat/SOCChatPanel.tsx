import React, { useState, useEffect, useRef } from 'react';
import { MessageSquare, Send, Bot, Users } from 'lucide-react';
import { useAuthStore } from '../../store/authStore';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';

interface ChatMessage {
  id: string;
  room_id: string;
  user_id: string;
  username: string;
  content: string;
  type: 'chat' | 'ai' | 'system';
  timestamp: string;
}

export default function SOCChatPanel({ roomId = 'soc-general' }: { roomId?: string }) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const token = useAuthStore((s) => s.token);
  const user = useAuthStore((s) => s.user);

  useEffect(() => {
    if (!token) return;
    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const baseUrl = import.meta.env.VITE_WS_URL || `${protocol}://${window.location.host}`;
    const url = `${baseUrl}/api/v1/ws/chat?token=${encodeURIComponent(token)}&room_id=${roomId}`;

    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'history') {
          setMessages(data.messages || []);
        } else if (data.type === 'system') {
          setMessages((prev) => [...prev, { ...data, type: 'system' } as ChatMessage]);
        } else {
          setMessages((prev) => [...prev, data]);
        }
      } catch {}
    };

    return () => ws.close();
  }, [token, roomId]);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' });
  }, [messages]);

  const send = () => {
    if (!input.trim() || !wsRef.current) return;
    wsRef.current.send(JSON.stringify({ content: input }));
    setInput('');
  };

  return (
    <div className="flex flex-col h-full bg-gray-900 border-l border-gray-800">
      <div className="flex items-center gap-2 px-3 py-2.5 border-b border-gray-800">
        <MessageSquare className="w-4 h-4 text-blue-400" />
        <span className="text-sm font-medium text-gray-200">SOC Chat</span>
        <span className={`ml-auto w-2 h-2 rounded-full ${connected ? 'bg-green-400' : 'bg-red-400'}`} />
      </div>

      <div ref={scrollRef} className="flex-1 overflow-y-auto p-3 space-y-2">
        {messages.map((msg, i) => (
          <div key={msg.id || i} className={`${msg.type === 'system' ? 'text-center' : ''}`}>
            {msg.type === 'system' ? (
              <p className="text-xs text-gray-600 italic">{msg.content}</p>
            ) : (
              <div className={`flex gap-2 ${msg.user_id === 'ai-assistant' ? 'items-start' : 'items-start'}`}>
                {msg.user_id === 'ai-assistant' ? (
                  <div className="w-6 h-6 rounded-full bg-blue-900 flex items-center justify-center flex-shrink-0 mt-0.5">
                    <Bot className="w-3.5 h-3.5 text-blue-400" />
                  </div>
                ) : (
                  <div className="w-6 h-6 rounded-full bg-gray-700 flex items-center justify-center flex-shrink-0 mt-0.5">
                    <Users className="w-3.5 h-3.5 text-gray-400" />
                  </div>
                )}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-1.5">
                    <span className={`text-xs font-medium ${msg.user_id === 'ai-assistant' ? 'text-blue-400' : 'text-gray-400'}`}>
                      {msg.username}
                    </span>
                    <span className="text-[10px] text-gray-600">
                      {new Date(msg.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </div>
                  <div className={`text-sm mt-0.5 whitespace-pre-wrap ${msg.user_id === 'ai-assistant' ? 'text-blue-200' : 'text-gray-200'}`}>
                    {msg.content}
                  </div>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      <div className="p-3 border-t border-gray-800">
        <div className="flex gap-2">
          <Input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && send()}
            placeholder="Ask AI or chat with team..."
            className="flex-1"
          />
          <Button onClick={send} size="sm" disabled={!input.trim()}>
            <Send className="w-4 h-4" />
          </Button>
        </div>
      </div>
    </div>
  );
}
