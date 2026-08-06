import { useState, useEffect, useCallback } from 'react';
import {
  Brain, Sparkles, TrendingUp, Shield, AlertTriangle,
  Send, Loader2, Lightbulb, Cpu, MessageSquare,
} from 'lucide-react';
import { clsx } from 'clsx';
import { Card, CardHeader, CardTitle } from '@/components/ui/Card';
import { api } from '@/services/api';

interface AIInsight {
  type: 'summary' | 'recommendation' | 'risk' | 'trend';
  title: string;
  content: string;
  severity?: string;
}

interface AISummary {
  insights: AIInsight[];
  risk_score: string;
  trend_direction: 'up' | 'down' | 'stable';
  trend_value: string;
}

const DUMMY_INSIGHTS: AIInsight[] = [
  {
    type: 'summary',
    title: 'Environment Overview',
    content: 'The platform is currently monitoring your security posture. Connect an AI API key to unlock real-time AI-powered insights, threat predictions, and automated analysis.',
    severity: 'info',
  },
  {
    type: 'recommendation',
    title: 'Getting Started',
    content: 'Set your OPENAI_API_KEY or AZURE_OPENAI_KEY in the environment configuration to enable AI features. Once configured, the system will provide intelligent security analysis, incident summaries, and actionable recommendations.',
  },
  {
    type: 'risk',
    title: 'AI Status',
    content: 'AI features are not yet configured. Security operations will continue using rule-based detection and manual analysis until AI is enabled.',
    severity: 'medium',
  },
];

export function AIInsights() {
  const [insights, setInsights] = useState<AIInsight[]>([]);
  const [summary, setSummary] = useState<AISummary | null>(null);
  const [question, setQuestion] = useState('');
  const [answer, setAnswer] = useState('');
  const [loading, setLoading] = useState(true);
  const [asking, setAsking] = useState(false);
  const [aiEnabled, setAiEnabled] = useState<boolean | null>(null);

  const fetchInsights = useCallback(async () => {
    try {
      const data = await api.get<{
        enabled: boolean;
        summary: AISummary;
        insights_count: number;
      }>('/ai/insights');
      setAiEnabled(data.enabled);
      if (data.enabled && data.summary) {
        setSummary(data.summary);
        setInsights(data.summary.insights || []);
      } else {
        setInsights(DUMMY_INSIGHTS);
      }
    } catch {
      setAiEnabled(false);
      setInsights(DUMMY_INSIGHTS);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchInsights();
  }, [fetchInsights]);

  const handleAskQuestion = async () => {
    const trimmed = question.trim();
    if (!trimmed || asking) return;
    setAsking(true);
    setAnswer('');
    try {
      const data = await api.post<{ answer: string }>('/ai/ask', {
        question: trimmed,
      });
      setAnswer(data.answer || 'No response received.');
    } catch {
      setAnswer(
        'Unable to reach the AI service. Please verify your API key configuration and that the AI service is running.'
      );
    } finally {
      setAsking(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleAskQuestion();
    }
  };

  const getIcon = (type: string) => {
    switch (type) {
      case 'summary':
        return Brain;
      case 'recommendation':
        return Lightbulb;
      case 'risk':
        return AlertTriangle;
      case 'trend':
        return TrendingUp;
      default:
        return Shield;
    }
  };

  const getIconColor = (type: string, severity?: string) => {
    if (severity === 'critical' || severity === 'high') return 'text-red-500';
    if (severity === 'medium') return 'text-amber-500';
    if (severity === 'low' || severity === 'info') return 'text-blue-500';
    switch (type) {
      case 'summary':
        return 'text-brand-500';
      case 'recommendation':
        return 'text-emerald-500';
      case 'risk':
        return 'text-red-500';
      case 'trend':
        return 'text-purple-500';
      default:
        return 'text-slate-500';
    }
  };

  const getIconBg = (type: string, severity?: string) => {
    if (severity === 'critical' || severity === 'high') return 'bg-red-50';
    if (severity === 'medium') return 'bg-amber-50';
    if (severity === 'low' || severity === 'info') return 'bg-blue-50';
    switch (type) {
      case 'summary':
        return 'bg-brand-50';
      case 'recommendation':
        return 'bg-emerald-50';
      case 'risk':
        return 'bg-red-50';
      case 'trend':
        return 'bg-purple-50';
      default:
        return 'bg-slate-50';
    }
  };

  const getTrendIcon = () => {
    if (!summary) return null;
    if (summary.trend_direction === 'up') {
      return <TrendingUp className="w-4 h-4 text-emerald-500" />;
    }
    if (summary.trend_direction === 'down') {
      return <TrendingUp className="w-4 h-4 text-red-500 rotate-180" />;
    }
    return <div className="w-4 h-4 rounded-full border-2 border-slate-300" />;
  };

  if (loading) {
    return (
      <Card className="min-h-[420px]">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-brand-500" />
            AI Insights
          </CardTitle>
          <div className="flex items-center gap-1.5">
            <Cpu className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">
              AI Powered
            </span>
          </div>
        </CardHeader>
        <div className="flex items-center justify-center py-16">
          <div className="flex flex-col items-center gap-3">
            <Loader2 className="w-8 h-8 text-brand-500 animate-spin" />
            <p className="text-sm text-slate-500">Analyzing security data...</p>
          </div>
        </div>
      </Card>
    );
  }

  return (
    <Card className="min-h-[420px]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Sparkles className="w-5 h-5 text-brand-500" />
          AI Insights
        </CardTitle>
        <div className="flex items-center gap-1.5">
          {aiEnabled ? (
            <>
              <div className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span className="text-[11px] font-medium text-emerald-600 uppercase tracking-wider">
                Live
              </span>
            </>
          ) : (
            <>
              <Cpu className="w-3.5 h-3.5 text-slate-400" />
              <span className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">
                Offline
              </span>
            </>
          )}
        </div>
      </CardHeader>

      {/* Summary Bar */}
      {summary && (
        <div className="mb-4 flex items-center gap-4 p-3 bg-gradient-to-r from-brand-50/80 to-transparent rounded-lg border border-brand-100/60">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-brand-600" />
            <span className="text-xs font-medium text-slate-500">Risk Score</span>
          </div>
          <span
            className={clsx(
              'text-lg font-bold tracking-tight',
              parseFloat(summary.risk_score) >= 70
                ? 'text-red-600'
                : parseFloat(summary.risk_score) >= 40
                  ? 'text-amber-600'
                  : 'text-emerald-600'
            )}
          >
            {summary.risk_score}
          </span>
          <div className="w-px h-8 bg-brand-200" />
          <div className="flex items-center gap-2">
            {getTrendIcon()}
            <div>
              <p className="text-[10px] font-medium text-slate-400 uppercase tracking-wider">Trend</p>
              <p
                className={clsx(
                  'text-xs font-semibold',
                  summary.trend_direction === 'up'
                    ? 'text-emerald-600'
                    : summary.trend_direction === 'down'
                      ? 'text-red-600'
                      : 'text-slate-500'
                )}
              >
                {summary.trend_value}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Insights Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4">
        {insights.slice(0, 4).map((insight, idx) => {
          const Icon = getIcon(insight.type);
          return (
            <div
              key={idx}
              className="flex gap-3 p-3 rounded-lg border border-slate-100 bg-slate-50/50 hover:border-brand-100 hover:bg-white transition-colors"
            >
              <div
                className={clsx(
                  'flex-shrink-0 w-8 h-8 rounded-lg flex items-center justify-center',
                  getIconBg(insight.type, insight.severity)
                )}
              >
                <Icon
                  className={clsx('w-4 h-4', getIconColor(insight.type, insight.severity))}
                />
              </div>
              <div className="min-w-0">
                <p className="text-xs font-semibold text-slate-700 truncate">
                  {insight.title}
                </p>
                <p className="text-xs text-slate-500 mt-0.5 line-clamp-2">
                  {insight.content}
                </p>
              </div>
            </div>
          );
        })}
      </div>

      {/* Chat Interface */}
      <div className="border-t border-slate-100 pt-4">
        <div className="flex items-center gap-2 mb-3">
          <MessageSquare className="w-4 h-4 text-slate-400" />
          <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">
            Ask AEGISX AI
          </span>
        </div>
        {answer && (
          <div className="mb-3 p-3 rounded-lg bg-brand-50/60 border border-brand-100/60">
            <p className="text-xs text-slate-700 whitespace-pre-wrap">{answer}</p>
          </div>
        )}
        <div className="flex gap-2">
          <input
            type="text"
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={aiEnabled ? 'Ask about your security posture...' : 'AI is offline — no questions can be processed'}
            disabled={!aiEnabled && aiEnabled !== null}
            className={clsx(
              'flex-1 px-3 py-2 text-sm rounded-lg border',
              'bg-white text-slate-900 placeholder:text-slate-400',
              'border-slate-200 focus:border-brand-400 focus:ring-2 focus:ring-brand-100',
              'outline-none transition-all',
              (!aiEnabled && aiEnabled !== null) && 'bg-slate-50 text-slate-400 cursor-not-allowed'
            )}
          />
          <button
            onClick={handleAskQuestion}
            disabled={!question.trim() || asking || (!aiEnabled && aiEnabled !== null)}
            className={clsx(
              'flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm font-medium transition-all',
              question.trim() && (aiEnabled || aiEnabled === null)
                ? 'bg-brand-600 text-white hover:bg-brand-700 active:scale-[0.97]'
                : 'bg-slate-100 text-slate-400 cursor-not-allowed'
            )}
          >
            {asking ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Send className="w-4 h-4" />
            )}
          </button>
        </div>
      </div>
    </Card>
  );
}
