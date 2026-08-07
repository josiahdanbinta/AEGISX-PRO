import { useState, useEffect, useCallback } from 'react';
import {
  Globe, Search, Plus, RefreshCw, Shield, Users, Target,
  Calendar, AlertTriangle, AlertCircle, ExternalLink, Database,
  Clock, ChevronDown, Filter, X, CheckCircle, XCircle, Wifi,
  Activity, Hash, MapPin, UserX,
} from 'lucide-react';
import { Card, CardHeader, CardTitle } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { Input } from '@/components/ui/Input';
import { Table } from '@/components/ui/Table';
import { Loading } from '@/components/ui/Loading';
import { Modal } from '@/components/ui/Modal';
import { api } from '@/services/api';
import type { ThreatIndicator, PaginatedResponse } from '@/types';

type TabName = 'indicators' | 'feeds' | 'actors' | 'campaigns' | 'mitre';

interface ThreatFeed {
  id: string;
  name: string;
  source_url: string;
  status: 'active' | 'error' | 'syncing';
  last_sync: string | null;
  indicator_count: number;
  enabled: boolean;
}

interface ThreatActor {
  id: string;
  name: string;
  aliases: string[];
  motivation: string;
  targeted_sectors: string[];
  sophistication: string;
  threat_level: string;
  description: string;
}

interface ThreatCampaign {
  id: string;
  name: string;
  description: string;
  first_seen: string;
  last_seen: string | null;
  status: string;
  threat_actors: Array<{ actor_id: string; name: string }>;
  targeted_sectors: string[];
}

interface MitreTechnique {
  id: string;
  name: string;
  description: string;
  tactics: string[];
  platforms: string[];
}

interface MitreTactic {
  id: string;
  name: string;
}

interface MitreResponse {
  tactics: MitreTactic[];
  techniques: MitreTechnique[];
}

const indicatorTypeIcons: Record<string, typeof Globe> = {
  ip: MapPin,
  domain: Globe,
  url: Globe,
  hash: Hash,
  email: Globe,
};

const tabOptions: { key: TabName; label: string }[] = [
  { key: 'indicators', label: 'Indicators' },
  { key: 'feeds', label: 'Feeds' },
  { key: 'actors', label: 'Actors' },
  { key: 'campaigns', label: 'Campaigns' },
  { key: 'mitre', label: 'MITRE ATT&CK' },
];

const typeOptions = [
  { value: '', label: 'All Types' },
  { value: 'ip', label: 'IP' },
  { value: 'domain', label: 'Domain' },
  { value: 'url', label: 'URL' },
  { value: 'hash', label: 'Hash' },
  { value: 'email', label: 'Email' },
];

const confidenceColor = (confidence: number): string => {
  if (confidence >= 80) return 'text-emerald-600 bg-emerald-50';
  if (confidence >= 60) return 'text-yellow-600 bg-yellow-50';
  if (confidence >= 40) return 'text-orange-600 bg-orange-50';
  return 'text-red-600 bg-red-50';
};

const feedStatusIcon = (status: string) => {
  switch (status) {
    case 'active': return <CheckCircle className="w-4 h-4 text-emerald-500" />;
    case 'error': return <XCircle className="w-4 h-4 text-red-500" />;
    case 'syncing': return <RefreshCw className="w-4 h-4 text-blue-500 animate-spin" />;
    default: return <Clock className="w-4 h-4 text-slate-400" />;
  }
};

const actorThreatBadge: Record<string, 'danger' | 'warning' | 'info' | 'default'> = {
  'critical': 'danger',
  'high': 'warning',
  'medium': 'info',
  'low': 'default',
};

export function ThreatIntelPage() {
  const [activeTab, setActiveTab] = useState<TabName>('indicators');

  // Indicators state
  const [indicators, setIndicators] = useState<ThreatIndicator[]>([]);
  const [indicatorLoading, setIndicatorLoading] = useState(true);
  const [indicatorError, setIndicatorError] = useState<string | null>(null);
  const [indicatorPage, setIndicatorPage] = useState(1);
  const [indicatorTotal, setIndicatorTotal] = useState(0);
  const [indicatorSearch, setIndicatorSearch] = useState('');
  const [indicatorType, setIndicatorType] = useState('');

  // Feeds state
  const [feeds, setFeeds] = useState<ThreatFeed[]>([]);
  const [feedLoading, setFeedLoading] = useState(true);
  const [feedError, setFeedError] = useState<string | null>(null);
  const [showAddFeed, setShowAddFeed] = useState(false);
  const [newFeedUrl, setNewFeedUrl] = useState('');
  const [newFeedName, setNewFeedName] = useState('');

  // Actors state
  const [actors, setActors] = useState<ThreatActor[]>([]);
  const [actorLoading, setActorLoading] = useState(true);
  const [actorError, setActorError] = useState<string | null>(null);

  // Campaigns state
  const [campaigns, setCampaigns] = useState<ThreatCampaign[]>([]);
  const [campaignLoading, setCampaignLoading] = useState(true);
  const [campaignError, setCampaignError] = useState<string | null>(null);

  // MITRE state
  const [mitreData, setMitreData] = useState<MitreTechnique[]>([]);
  const [mitreTacticsList, setMitreTacticsList] = useState<MitreTactic[]>([]);
  const [mitreLoading, setMitreLoading] = useState(true);
  const [mitreError, setMitreError] = useState<string | null>(null);

  // Load indicators
  const fetchIndicators = useCallback(() => {
    setIndicatorLoading(true);
    setIndicatorError(null);
    const params: Record<string, string> = { page: String(indicatorPage) };
    if (indicatorSearch) params.search = indicatorSearch;
    if (indicatorType) params.type = indicatorType;
    api.get<PaginatedResponse<ThreatIndicator>>('/threat-intel/indicators', { params })
      .then((res) => {
        const data = (res as unknown as { items: ThreatIndicator[] }).items;
        const meta = (res as unknown as { meta: { total_items: number } }).meta;
        if (Array.isArray(data)) setIndicators(data);
        if (meta) setIndicatorTotal(meta.total_items);
      })
      .catch((err) => setIndicatorError(err?.error?.message || 'Failed to load indicators'))
      .finally(() => setIndicatorLoading(false));
  }, [indicatorPage, indicatorSearch, indicatorType]);

  useEffect(() => {
    if (activeTab === 'indicators') fetchIndicators();
  }, [activeTab, fetchIndicators]);

  // Load feeds
  const fetchFeeds = useCallback(() => {
    setFeedLoading(true);
    setFeedError(null);
    api.get<ThreatFeed[]>('/threat-intel/feeds')
      .then((res) => {
        const data = (res as unknown as { items: ThreatFeed[] }).items;
        if (Array.isArray(data)) setFeeds(data);
      })
      .catch((err) => setFeedError(err?.error?.message || 'Failed to load feeds'))
      .finally(() => setFeedLoading(false));
  }, []);

  useEffect(() => {
    if (activeTab === 'feeds') fetchFeeds();
  }, [activeTab, fetchFeeds]);

  // Load actors
  const fetchActors = useCallback(() => {
    setActorLoading(true);
    setActorError(null);
    api.get<ThreatActor[]>('/threat-intel/actors')
      .then((res) => {
        const data = (res as unknown as { items: ThreatActor[] }).items;
        if (Array.isArray(data)) setActors(data);
      })
      .catch((err) => setActorError(err?.error?.message || 'Failed to load threat actors'))
      .finally(() => setActorLoading(false));
  }, []);

  useEffect(() => {
    if (activeTab === 'actors') fetchActors();
  }, [activeTab, fetchActors]);

  // Load campaigns
  const fetchCampaigns = useCallback(() => {
    setCampaignLoading(true);
    setCampaignError(null);
    api.get<ThreatCampaign[]>('/threat-intel/campaigns')
      .then((res) => {
        const data = (res as unknown as { items: ThreatCampaign[] }).items;
        if (Array.isArray(data)) setCampaigns(data);
      })
      .catch((err) => setCampaignError(err?.error?.message || 'Failed to load campaigns'))
      .finally(() => setCampaignLoading(false));
  }, []);

  useEffect(() => {
    if (activeTab === 'campaigns') fetchCampaigns();
  }, [activeTab, fetchCampaigns]);

  // Load MITRE
  const fetchMitre = useCallback(() => {
    setMitreLoading(true);
    setMitreError(null);
    api.get<MitreResponse>('/threat-intel/mitre')
      .then((res) => {
        const data = res as unknown as { techniques: MitreTechnique[]; tactics: MitreTactic[] };
        if (data.techniques) setMitreData(data.techniques);
        if (data.tactics) setMitreTacticsList(data.tactics);
      })
      .catch((err) => setMitreError(err?.error?.message || 'Failed to load MITRE data'))
      .finally(() => setMitreLoading(false));
  }, []);

  useEffect(() => {
    if (activeTab === 'mitre') fetchMitre();
  }, [activeTab, fetchMitre]);

  const handleAddFeed = async () => {
    if (!newFeedName || !newFeedUrl) return;
    try {
      await api.post('/threat-intel/feeds', { name: newFeedName, source_url: newFeedUrl });
      setShowAddFeed(false);
      setNewFeedName('');
      setNewFeedUrl('');
      fetchFeeds();
    } catch (err: unknown) {
      const message = (err as { error?: { message?: string } })?.error?.message || 'Failed to add feed';
      setFeedError(message);
    }
  };

  const indicatorColumns = [
    {
      key: 'type', header: 'Type', width: '80px',
      render: (row: ThreatIndicator) => {
        const Icon = indicatorTypeIcons[row.type] || Globe;
        return (
          <div className="flex items-center gap-1.5">
            <Icon className="w-3.5 h-3.5 text-slate-500" />
            <span className="text-xs font-medium uppercase text-slate-600">{row.type}</span>
          </div>
        );
      },
    },
    {
      key: 'value', header: 'Value',
      render: (row: ThreatIndicator) => (
        <code className="text-xs bg-slate-100 px-1.5 py-0.5 rounded font-mono text-slate-700">{row.value}</code>
      ),
    },
    {
      key: 'confidence', header: 'Confidence', width: '100px',
      render: (row: ThreatIndicator) => (
        <div className="flex items-center gap-2">
          <div className="w-12 h-1.5 bg-slate-100 rounded-full overflow-hidden">
            <div className="h-full bg-emerald-500 rounded-full" style={{ width: `${row.confidence}%` }} />
          </div>
          <span className="text-xs font-medium text-slate-600">{row.confidence}%</span>
        </div>
      ),
    },
    {
      key: 'source', header: 'Source', width: '120px',
      render: (row: ThreatIndicator) => (
        <span className="text-xs text-slate-600">{row.source}</span>
      ),
    },
    {
      key: 'tags', header: 'Tags', width: '160px',
      render: (row: ThreatIndicator) => (
        <div className="flex flex-wrap gap-1">
          {row.tags.slice(0, 3).map((t) => (
            <Badge key={t} variant="default" size="sm">{t}</Badge>
          ))}
          {row.tags.length > 3 && (
            <Badge variant="default" size="sm">+{row.tags.length - 3}</Badge>
          )}
        </div>
      ),
    },
    {
      key: 'first_seen', header: 'First Seen', width: '110px',
      render: (row: ThreatIndicator) => (
        <span className="text-xs text-slate-500">{row.first_seen ? new Date(row.first_seen).toLocaleDateString() : '—'}</span>
      ),
    },
    {
      key: 'last_seen', header: 'Last Seen', width: '110px',
      render: (row: ThreatIndicator) => (
        <span className="text-xs text-slate-500">{row.last_seen ? new Date(row.last_seen).toLocaleDateString() : '—'}</span>
      ),
    },
  ];

  // Group MITRE data by tactic
  const mitreByTactic = mitreData.reduce<Record<string, MitreTechnique[]>>((acc, item) => {
    for (const tid of item.tactics) {
      const tactic = mitreTacticsList.find((t) => t.id === tid);
      const name = tactic?.name || tid;
      if (!acc[name]) acc[name] = [];
      acc[name].push(item);
    }
    return acc;
  }, {});

  function getHeatColor(count: number): string {
    if (ratio === 0) return 'bg-slate-50';
    if (ratio < 0.2) return 'bg-emerald-100';
    if (ratio < 0.4) return 'bg-yellow-100';
    if (ratio < 0.6) return 'bg-orange-200';
    if (ratio < 0.8) return 'bg-red-200';
    return 'bg-red-400';
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-900">Threat Intelligence</h1>
        <p className="text-sm text-slate-500 mt-1">Global threat data, indicators, and adversary insights</p>
      </div>

      <div className="flex border-b border-slate-200 gap-1">
        {tabOptions.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px ${
              activeTab === tab.key
                ? 'border-brand-600 text-brand-700'
                : 'border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* INDICATORS TAB */}
      {activeTab === 'indicators' && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-3">
            <div className="relative flex-1 min-w-[200px] max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
              <Input
                placeholder="Search indicators..."
                value={indicatorSearch}
                onChange={(e) => { setIndicatorSearch(e.target.value); setIndicatorPage(1); }}
                className="pl-9"
              />
            </div>
            <div className="relative">
              <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
              <select
                value={indicatorType}
                onChange={(e) => { setIndicatorType(e.target.value); setIndicatorPage(1); }}
                className="appearance-none bg-white border border-slate-200 rounded-lg pl-9 pr-8 py-2 text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500 cursor-pointer"
              >
                {typeOptions.map((o) => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
              <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 pointer-events-none" />
            </div>
          </div>

          {indicatorError && (
            <div className="flex flex-col items-center justify-center py-16 gap-3">
              <AlertCircle className="w-10 h-10 text-red-400" />
              <p className="text-red-600 font-medium">{indicatorError}</p>
              <Button variant="secondary" size="sm" onClick={fetchIndicators}>Retry</Button>
            </div>
          )}

          {!indicatorError && (
            <Card padding="none">
              <Table
                columns={indicatorColumns}
                data={(indicators as unknown) as Record<string, unknown>[]}
                keyExtractor={(row) => String(row.id)}
                page={indicatorPage}
                pageSize={20}
                total={indicatorTotal}
                onPageChange={setIndicatorPage}
                loading={indicatorLoading}
              />
            </Card>
          )}
        </div>
      )}

      {/* FEEDS TAB */}
      {activeTab === 'feeds' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-slate-500">
              {feeds.length} feed{feeds.length !== 1 ? 's' : ''} configured
            </p>
            <Button size="sm" onClick={() => setShowAddFeed(true)}>
              <Plus className="w-4 h-4" />
              Add Feed
            </Button>
          </div>

          {feedError && (
            <div className="flex flex-col items-center justify-center py-16 gap-3">
              <AlertCircle className="w-10 h-10 text-red-400" />
              <p className="text-red-600 font-medium">{feedError}</p>
              <Button variant="secondary" size="sm" onClick={fetchFeeds}>Retry</Button>
            </div>
          )}

          {feedLoading && (
            <div className="flex flex-col items-center justify-center py-16">
              <Loading size="md" text="Loading feeds..." />
            </div>
          )}

          {!feedLoading && !feedError && feeds.length === 0 && (
            <Card>
              <div className="flex flex-col items-center justify-center py-12 gap-3">
                <Database className="w-10 h-10 text-slate-300" />
                <p className="text-slate-500 font-medium">No threat feeds configured</p>
                <p className="text-sm text-slate-400">Add a feed to start ingesting threat intelligence</p>
                <Button variant="secondary" size="sm" onClick={() => setShowAddFeed(true)}>
                  <Plus className="w-4 h-4" />
                  Add Feed
                </Button>
              </div>
            </Card>
          )}

          {!feedLoading && !feedError && feeds.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {feeds.map((feed) => (
                <Card key={feed.id} hover>
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      <div className={`p-2 rounded-lg ${feed.status === 'active' ? 'bg-emerald-50' : feed.status === 'error' ? 'bg-red-50' : 'bg-blue-50'}`}>
                        {feedStatusIcon(feed.status)}
                      </div>
                      <div>
                        <h3 className="font-medium text-slate-900">{feed.name}</h3>
                        <p className="text-xs text-slate-400 mt-0.5 truncate max-w-[280px]">{feed.source_url}</p>
                      </div>
                    </div>
                    <Badge
                      variant={feed.status === 'active' ? 'success' : feed.status === 'error' ? 'danger' : 'info'}
                      size="sm"
                    >
                      {feed.status}
                    </Badge>
                  </div>
                  <div className="flex items-center gap-4 mt-4 pt-4 border-t border-slate-100">
                    <div className="flex items-center gap-1.5 text-xs text-slate-500">
                      <Shield className="w-3.5 h-3.5" />
                      {feed.indicator_count.toLocaleString()} IOCs
                    </div>
                    <div className="flex items-center gap-1.5 text-xs text-slate-500">
                      <Clock className="w-3.5 h-3.5" />
                      {feed.last_sync ? new Date(feed.last_sync).toLocaleString() : 'Never synced'}
                    </div>
                  </div>
                </Card>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ACTORS TAB */}
      {activeTab === 'actors' && (
        <div className="space-y-4">
          {actorError && (
            <div className="flex flex-col items-center justify-center py-16 gap-3">
              <AlertCircle className="w-10 h-10 text-red-400" />
              <p className="text-red-600 font-medium">{actorError}</p>
              <Button variant="secondary" size="sm" onClick={fetchActors}>Retry</Button>
            </div>
          )}

          {actorLoading && (
            <div className="flex flex-col items-center justify-center py-16">
              <Loading size="md" text="Loading threat actors..." />
            </div>
          )}

          {!actorLoading && !actorError && actors.length === 0 && (
            <Card>
              <div className="flex flex-col items-center justify-center py-12 gap-3">
                <Users className="w-10 h-10 text-slate-300" />
                <p className="text-slate-500 font-medium">No threat actors found</p>
              </div>
            </Card>
          )}

          {!actorLoading && !actorError && actors.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {actors.map((actor) => (
                <Card key={actor.id} hover>
                  <div className="flex items-start gap-3 mb-3">
                    <div className="w-12 h-12 rounded-xl bg-slate-100 flex items-center justify-center flex-shrink-0">
                      <UserX className="w-6 h-6 text-slate-500" />
                    </div>
                    <div className="min-w-0">
                      <h3 className="font-semibold text-slate-900 truncate">{actor.name}</h3>
                      {actor.aliases.length > 0 && (
                        <p className="text-xs text-slate-400 mt-0.5 truncate">aka {actor.aliases.slice(0, 2).join(', ')}</p>
                      )}
                    </div>
                  </div>
                  <div className="space-y-2">
                    <div className="flex items-center gap-1.5 text-xs text-slate-500">
                      <Target className="w-3.5 h-3.5" />
                      <span className="font-medium">Motivation:</span> {actor.motivation}
                    </div>
                    <div className="flex items-start gap-1.5 text-xs text-slate-500">
                      <Shield className="w-3.5 h-3.5 mt-0.5" />
                      <span className="font-medium">Targets:</span>
                      <span>{actor.targeted_sectors.join(', ')}</span>
                    </div>
                    <div className="flex items-center gap-1.5 text-xs text-slate-500">
                      <Activity className="w-3.5 h-3.5" />
                      <span className="font-medium">Level:</span>
                      <Badge variant={actorThreatBadge[actor.threat_level] || 'default'} size="sm">
                        {actor.threat_level}
                      </Badge>
                    </div>
                  </div>
                </Card>
              ))}
            </div>
          )}
        </div>
      )}

      {/* CAMPAIGNS TAB */}
      {activeTab === 'campaigns' && (
        <div className="space-y-4">
          {campaignError && (
            <div className="flex flex-col items-center justify-center py-16 gap-3">
              <AlertCircle className="w-10 h-10 text-red-400" />
              <p className="text-red-600 font-medium">{campaignError}</p>
              <Button variant="secondary" size="sm" onClick={fetchCampaigns}>Retry</Button>
            </div>
          )}

          {campaignLoading && (
            <div className="flex flex-col items-center justify-center py-16">
              <Loading size="md" text="Loading campaigns..." />
            </div>
          )}

          {!campaignLoading && !campaignError && campaigns.length === 0 && (
            <Card>
              <div className="flex flex-col items-center justify-center py-12 gap-3">
                <Target className="w-10 h-10 text-slate-300" />
                <p className="text-slate-500 font-medium">No active campaigns</p>
              </div>
            </Card>
          )}

          {!campaignLoading && !campaignError && campaigns.length > 0 && (
            <div className="space-y-4">
              {campaigns.map((campaign) => (
                <Card key={campaign.id} hover>
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-3">
                      <div className={`p-2 rounded-lg ${campaign.status === 'active' ? 'bg-red-50' : 'bg-slate-100'}`}>
                        <Target className={`w-5 h-5 ${campaign.status === 'active' ? 'text-red-500' : 'text-slate-400'}`} />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <h3 className="font-semibold text-slate-900">{campaign.name}</h3>
                          <Badge variant={campaign.status === 'active' ? 'danger' : 'default'} size="sm">
                            {campaign.status}
                          </Badge>
                        </div>
                        <p className="text-sm text-slate-500 mt-1">{campaign.description}</p>
                      </div>
                    </div>
                    <div className="text-right">
                  <div className="flex items-center gap-1.5 text-xs text-slate-500">
                    <Calendar className="w-3.5 h-3.5" />
                    <span>{new Date(campaign.first_seen).toLocaleDateString()}</span>
                    {campaign.last_seen && (
                      <span> – {new Date(campaign.last_seen).toLocaleDateString()}</span>
                    )}
                      </div>
                    </div>
                  </div>
                  <div className="flex flex-wrap items-center gap-3 mt-3 pt-3 border-t border-slate-100">
                    {campaign.threat_actors?.length > 0 && (
                      <div className="flex items-center gap-1.5 text-xs text-slate-500">
                        <Users className="w-3.5 h-3.5" />
                        <span className="font-medium">Actors:</span>
                        {campaign.threat_actors.map((a: { name: string }) => a.name).join(', ')}
                      </div>
                    )}
                    {campaign.targeted_sectors.length > 0 && (
                      <div className="flex items-center gap-1.5 text-xs text-slate-500">
                        <Shield className="w-3.5 h-3.5" />
                        <span className="font-medium">Sectors:</span>
                        {campaign.targeted_sectors.join(', ')}
                      </div>
                    )}
                  </div>
                </Card>
              ))}
            </div>
          )}
        </div>
      )}

      {/* MITRE ATT&CK TAB */}
      {activeTab === 'mitre' && (
        <div className="space-y-4">
          {mitreError && (
            <div className="flex flex-col items-center justify-center py-16 gap-3">
              <AlertCircle className="w-10 h-10 text-red-400" />
              <p className="text-red-600 font-medium">{mitreError}</p>
              <Button variant="secondary" size="sm" onClick={fetchMitre}>Retry</Button>
            </div>
          )}

          {mitreLoading && (
            <div className="flex flex-col items-center justify-center py-16">
              <Loading size="md" text="Loading MITRE data..." />
            </div>
          )}

          {!mitreLoading && !mitreError && mitreData.length === 0 && (
            <Card>
              <div className="flex flex-col items-center justify-center py-12 gap-3">
                <Shield className="w-10 h-10 text-slate-300" />
                <p className="text-slate-500 font-medium">No MITRE ATT&CK data available</p>
              </div>
            </Card>
          )}

          {!mitreLoading && !mitreError && mitreData.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>MITRE ATT&CK Coverage</CardTitle>
                <span className="text-xs text-slate-400">Tactics x Techniques heatmap by incident count</span>
              </CardHeader>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr>
                      <th className="text-left text-xs font-semibold text-slate-500 uppercase tracking-wider px-3 py-2 bg-slate-50 border-b border-slate-200 sticky left-0 z-10">
                        Technique
                      </th>
                      {mitreTacticsList.map((tactic) => (
                        <th
                          key={tactic}
                          className="text-center text-[10px] font-semibold text-slate-500 uppercase tracking-wider px-2 py-2 bg-slate-50 border-b border-slate-200"
                          style={{ minWidth: '90px', maxWidth: '90px', writingMode: 'horizontal-tb' }}
                        >
                          {tactic}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {mitreData.map((item) => (
                      <tr key={item.id} className="border-b border-slate-100 hover:bg-slate-50 transition-colors">
                        <td className="px-3 py-2 sticky left-0 bg-white">
                          <div className="flex items-center gap-2">
                            <code className="text-[10px] bg-slate-100 px-1.5 py-0.5 rounded font-mono text-slate-600 whitespace-nowrap">
                              {item.id}
                            </code>
                            <span className="text-xs text-slate-700 truncate max-w-[180px]" title={item.name}>{item.name}</span>
                          </div>
                        </td>
                        {mitreTacticsList.map((tactic) => {
                          const match = mitreByTactic[tactic]?.find((m) => m.id === item.id);
                          return (
                            <td key={tactic} className="px-2 py-2 text-center" style={{ minWidth: '90px' }}>
                              {match ? (
                                <div className="w-full h-7 rounded bg-brand-100 flex items-center justify-center">
                                  <span className="w-3 h-3 rounded-full bg-brand-500" />
                                </div>
                              ) : (
                                <div className="w-full h-7 rounded bg-slate-50" />
                              )}
                            </td>
                          );
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="flex items-center gap-4 p-4 border-t border-slate-100">
                <span className="text-xs text-slate-500">Heatmap scale:</span>
                <div className="flex items-center gap-1">
                  <div className="w-5 h-3 rounded-sm bg-emerald-100" />
                  <div className="w-5 h-3 rounded-sm bg-yellow-100" />
                  <div className="w-5 h-3 rounded-sm bg-orange-200" />
                  <div className="w-5 h-3 rounded-sm bg-red-200" />
                  <div className="w-5 h-3 rounded-sm bg-red-400" />
                </div>
                <span className="text-xs text-slate-400">Low → High</span>
              </div>
            </Card>
          )}
        </div>
      )}

      {/* Add Feed Modal */}
      <Modal open={showAddFeed} onClose={() => setShowAddFeed(false)} title="Add Threat Feed">
        <div className="space-y-4">
          <Input
            label="Feed Name"
            placeholder="e.g. AlienVault OTX"
            value={newFeedName}
            onChange={(e) => setNewFeedName(e.target.value)}
          />
          <Input
            label="Feed URL"
            placeholder="https://..."
            value={newFeedUrl}
            onChange={(e) => setNewFeedUrl(e.target.value)}
          />
          <div className="flex items-center justify-end gap-2 pt-2">
            <Button variant="secondary" onClick={() => setShowAddFeed(false)}>Cancel</Button>
            <Button onClick={handleAddFeed} disabled={!newFeedName || !newFeedUrl}>
              <Plus className="w-4 h-4" />
              Add Feed
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
