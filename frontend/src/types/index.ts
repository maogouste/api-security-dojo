// API Types for VulnAPI Frontend

export interface Vulnerability {
  id: string;
  name: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  owasp: string;
  cwe: string;
  description: string;
}

export interface VulnerabilityDetail extends Vulnerability {
  vulnerable_endpoint: string;
  exploitation: {
    steps: string[];
    example_request: string;
    example_response: string;
  };
  vulnerable_code: string;
  secure_code: string;
  remediation: string[];
  references: string[];
  flag?: string;
}

export interface Challenge {
  id: string;
  name: string;
  category: string;
  difficulty: 'easy' | 'medium' | 'hard';
  points: number;
  description: string;
  hints: string[];
  flag_format: string;
  endpoints: string[];
  references: string[];
}

export interface ApiMode {
  mode: 'challenge' | 'documentation';
  documentation_enabled: boolean;
  description: string;
}

export interface ApiStats {
  total: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  rest_api: number;
  graphql: number;
}

export interface Category {
  name: string;
  count: number;
  vulnerabilities: string[];
}

export interface FlagResult {
  success: boolean;
  message: string;
  points?: number;
}

export interface User {
  id: number;
  username: string;
  email: string;
  role: string;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  user_id: number;
  role: string;
}

export interface ApiResponse<T> {
  data?: T;
  error?: string;
}
