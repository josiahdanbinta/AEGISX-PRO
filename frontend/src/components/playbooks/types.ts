export type PlaybookNode = {
  id: string;
  type: 'trigger' | 'condition' | 'action';
  label: string;
  actionType?: string;
  condition?: string;
  x: number;
  y: number;
  branches?: string[];
};

export type PlaybookEdge = {
  from: string;
  to: string;
  label?: string;
  branchId?: string;
};

export type Playbook = {
  id: string;
  name: string;
  description: string;
  triggerType: string;
  nodes: PlaybookNode[];
  edges: PlaybookEdge[];
  status: string;
};
