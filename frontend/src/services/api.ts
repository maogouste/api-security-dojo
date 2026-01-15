import axios from 'axios';
import type {
  Vulnerability,
  VulnerabilityDetail,
  ApiMode,
  ApiStats,
  Category,
  FlagResult,
  AuthResponse,
} from '../types';

// Get the base URL from localStorage or default to FastAPI
function getBaseUrl(): string {
  const backendId = localStorage.getItem('vulnapi_backend') || 'fastapi';
  const backends: Record<string, string> = {
    fastapi: 'http://localhost:8000',
    express: 'http://localhost:3001',
    go: 'http://localhost:3002',
    php: 'http://localhost:3003',
    java: 'http://localhost:3004',
    rust: 'http://localhost:3006',
  };
  return backends[backendId] || backends.fastapi;
}

// Create axios instance with dynamic base URL
const createApi = () => {
  const instance = axios.create({
    baseURL: getBaseUrl() + '/api',
    headers: {
      'Content-Type': 'application/json',
    },
  });

  // Add auth token to requests if available
  instance.interceptors.request.use((config) => {
    // Update base URL on each request in case backend changed
    config.baseURL = getBaseUrl() + '/api';

    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  });

  return instance;
};

const api = createApi();

// Documentation API
export const docsApi = {
  getMode: async (): Promise<ApiMode> => {
    const response = await api.get('/docs/mode');
    return response.data;
  },

  getStats: async (): Promise<ApiStats> => {
    const response = await api.get('/docs/stats');
    return response.data;
  },

  getCategories: async (): Promise<Category[]> => {
    const response = await api.get('/docs/categories');
    return response.data;
  },

  getVulnerabilities: async (category?: string): Promise<Vulnerability[]> => {
    const params = category ? { category } : {};
    const response = await api.get('/docs/vulnerabilities', { params });
    return response.data;
  },

  getVulnerability: async (id: string): Promise<VulnerabilityDetail> => {
    const response = await api.get(`/docs/vulnerabilities/${id}`);
    return response.data;
  },

  getCompareList: async (): Promise<{ id: string; name: string; key_difference: string }[]> => {
    const response = await api.get('/docs/compare');
    return response.data;
  },

  getCompare: async (id: string): Promise<{
    id: string;
    name: string;
    vulnerable_code: string;
    secure_code: string;
    key_difference: string;
    remediation: string[];
    owasp: string;
    cwe: string;
  }> => {
    const response = await api.get(`/docs/compare/${id}`);
    return response.data;
  },
};

// Auth API
export const authApi = {
  login: async (username: string, password: string): Promise<AuthResponse> => {
    const response = await api.post('/login', { username, password });
    return response.data;
  },

  register: async (username: string, email: string, password: string): Promise<AuthResponse> => {
    const response = await api.post('/register', { username, email, password });
    return response.data;
  },

  getCurrentUser: async () => {
    const response = await api.get('/me');
    return response.data;
  },
};

// Flags API
export const flagsApi = {
  submit: async (flag: string): Promise<FlagResult> => {
    const response = await api.post('/flags/submit', { flag });
    return response.data;
  },

  getProgress: async () => {
    const response = await api.get('/flags/progress');
    return response.data;
  },
};

export interface RequestResult {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  data: unknown;
}

// Generic API call for the console
export const executeRequest = async (
  method: string,
  endpoint: string,
  body?: unknown,
  headers?: Record<string, string>
): Promise<RequestResult> => {
  try {
    const baseUrl = getBaseUrl();
    const url = endpoint.startsWith('http')
      ? endpoint
      : baseUrl + (endpoint.startsWith('/') ? endpoint : '/' + endpoint);

    // Build headers with auth token if available
    const requestHeaders: Record<string, string> = {
      'Content-Type': 'application/json',
      ...headers,
    };

    const token = localStorage.getItem('token');
    if (token && !headers?.Authorization) {
      requestHeaders.Authorization = `Bearer ${token}`;
    }

    const config = {
      method: method.toLowerCase(),
      url,
      data: body,
      headers: requestHeaders,
    };

    const response = await axios({
      ...config,
      validateStatus: () => true, // Don't throw on error status
    });

    // Convert headers to simple Record<string, string>
    const responseHeaders: Record<string, string> = {};
    Object.entries(response.headers).forEach(([key, value]) => {
      if (typeof value === 'string') {
        responseHeaders[key] = value;
      }
    });

    return {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
      data: response.data,
    };
  } catch (error) {
    if (axios.isAxiosError(error)) {
      return {
        status: error.response?.status || 0,
        statusText: error.message,
        headers: {},
        data: error.response?.data || { error: error.message },
      };
    }
    throw error;
  }
};

// Export base URL getter for components that need it
export const getCurrentBaseUrl = getBaseUrl;

export default api;
